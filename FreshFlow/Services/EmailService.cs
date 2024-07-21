using FreshFlow.Models;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace FreshFlow.Services
{
    public class EmailService : IEmailService
    {
        private readonly EmailConfiguration _emailConfig;
        public EmailService(EmailConfiguration emailConfig) => _emailConfig = emailConfig;


        public void SendEmail(Message message)
        {
            var emailMessage = CreateEmailMessage(message);
            Send(emailMessage);
        }



        private MimeMessage CreateEmailMessage(Message message)
        {
            var emailMessage = new MimeMessage();
            emailMessage.From.Add(new MailboxAddress("email", "sisekelozimu@gmail.com"));
            emailMessage.To.AddRange(message.To);
            emailMessage.Subject = message.Subject;
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text) { Text = message.Content };
            return emailMessage;


        }
        private void Send(MimeMessage mailMessage)
        {
            using var client = new SmtpClient();
            try
            {

                client.Connect("smtp.gmail.com", 587, SecureSocketOptions.StartTls);
                client.AuthenticationMechanisms.Remove("XOAUTH2");
                client.Authenticate("sisekelozimu@gmail.com", "tvnezvcdvbcuxpyd");

                client.Send(mailMessage);
            }
            catch
            {
                //log an error message or throw an exception or both
                throw;

            }
            finally
            {
                client.Disconnect(true);
                client.Dispose();

            }
        }
        
    }
}
