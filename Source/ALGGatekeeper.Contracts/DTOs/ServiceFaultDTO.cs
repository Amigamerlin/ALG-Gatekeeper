using System.Runtime.Serialization;

namespace ALGGatekeeper.Contracts.DTO
{

    public enum ServiceErorCode
    {
        clientNotAdministrator = 01,
        invalidArgument = 02,
        internalError = 03
    }

    [DataContract]
    public class ServiceFaultDTO
    {
        /// <summary>
        /// Fault Code List
        /// 
        /// 01 - Client is not an Administrator, Client will be stopped!
        /// 02 - An argument sent by the client was rejected (e.g. an invalid white list pattern)
        /// 03 - The service could not complete the operation (details are in the message)
        /// 
        /// </summary>


        [DataMember]
        public ServiceErorCode Code { get; set; }
        [DataMember]
        public string Message { get; set; }
        [DataMember]
        public string Description { get; set; }
        [DataMember]
        public bool CanTerminate { get; set; }

        public ServiceFaultDTO(ServiceErorCode _code, string _message, bool _canTerminate = false, string _description = "")
        {
            Code = _code;
            Message = _message;
            Description = _description;
            CanTerminate = _canTerminate;
        }
    }
}
