using FreshFlow.Models;

namespace FreshFlow.Services
{
    public interface IEmailService
    {
        
        void SendEmail(Message message);
    }
}
