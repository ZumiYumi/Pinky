using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace PinDialogDemo
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            using (var dlg = new PinDialog())
            {
                var result = dlg.ShowDialog();
                if (result == DialogResult.OK)
                {
                    MessageBox.Show($"You entered PIN: {dlg.PIN}",
                                    "Result",
                                    MessageBoxButtons.OK,
                                    MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show("Authentication cancelled.",
                                    "Result",
                                    MessageBoxButtons.OK,
                                    MessageBoxIcon.Warning);
                }
            }
        }
    }

    public class PinDialog : Form
    {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr SendMessage(
            IntPtr hWnd, int msg, IntPtr wParam, [MarshalAs(UnmanagedType.LPWStr)] string lParam);
        private const int EM_SETCUEBANNER = 0x1501;

        public string PIN => _txtPin.Text;

        private readonly PictureBox _pbIcon;
        private readonly Label _lblTitle;
        private readonly Label _lblPrompt;
        private readonly Label _lblInstruction;
        private readonly TextBox _txtPin;
        private readonly LinkLabel _lnkForgot;
        private readonly Button _btnOk;
        private readonly Button _btnCancel;

        public PinDialog()
        {
            Text = "Windows Security";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(455, 235);
            BackColor = Color.FromArgb(242, 242, 242);
            MaximizeBox = false;
            MinimizeBox = false;

            _lblTitle = new Label
            {
                Text = "Smart Card",
                Font = new Font("Segoe UI", 14F, FontStyle.Regular, GraphicsUnit.Point),
                Location = new Point(20, 10),
                AutoSize = true
            };
            Controls.Add(_lblTitle);

            _lblInstruction = new Label
            {
                Text = "Please enter your PIN.",
                Font = new Font("Segoe UI", 10F, FontStyle.Regular, GraphicsUnit.Point),
                Location = new Point(_lblTitle.Left, _lblTitle.Bottom + 20),
                AutoSize = true
            };
            Controls.Add(_lblInstruction);

            _lblPrompt = new Label
            {
                Text = "",
                Location = new Point(80, 80),
                AutoSize = true
            };
            Controls.Add(_lblPrompt);

            _txtPin = new TextBox
            {
                Location = new Point(80 + _lblPrompt.PreferredWidth + 6, 76 + 20),
                Width = 300,
                Height = 20,
                UseSystemPasswordChar = true
            };
            Controls.Add(_txtPin);

            _pbIcon = new PictureBox
            {
                Size = new Size(48, 48),
                Location = new Point(_txtPin.Left - 56 - 8, _txtPin.Top),
                Image = Image.FromFile("SmartCardIcon.png"),
                SizeMode = PictureBoxSizeMode.StretchImage
            };
            Controls.Add(_pbIcon);


            SendMessage(_txtPin.Handle, EM_SETCUEBANNER, IntPtr.Zero, "PIN");

            _lnkForgot = new LinkLabel
            {
                Text = "Click here for more information",
                Location = new Point(_txtPin.Left - 5, 130),
                AutoSize = true,
                LinkBehavior = LinkBehavior.NeverUnderline
            };
            _lnkForgot.Click += (s, e) =>
            {
                MessageBox.Show(
                    "Your PIN will be returned in plaintext. The application may be able to access your PIN. Only enter your PIN if you trust the calling application.",
                    "Help",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            };
            Controls.Add(_lnkForgot);

            _btnOk = new Button
            {
                Text = "OK",
                Font = new Font("Segoe UI", 10F, FontStyle.Regular, GraphicsUnit.Point),
                DialogResult = DialogResult.OK,
                Location = new Point(20, 185),
                Size = new Size(205, 35),
                BackColor = Color.FromArgb(205, 205, 205)
            };
            Controls.Add(_btnOk);

            _btnCancel = new Button
            {
                Text = "Cancel",
                Font = new Font("Segoe UI", 10F, FontStyle.Regular, GraphicsUnit.Point),
                DialogResult = DialogResult.Cancel,
                Location = new Point(228, 185),
                Size = new Size(205, 35),
                BackColor = Color.FromArgb(205, 205, 205)
            };
            Controls.Add(_btnCancel);

            AcceptButton = _btnOk;
            CancelButton = _btnCancel;
        }
    }
}
