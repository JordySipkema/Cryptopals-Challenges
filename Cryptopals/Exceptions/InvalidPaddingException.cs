using System;
using System.Runtime.Serialization;

namespace Cryptopals.Exceptions
{
	public class InvalidPaddingException : Exception
	{
		public InvalidPaddingException()
		{
		}

        public InvalidPaddingException(string? message) : base(message)
        {
        }

        public InvalidPaddingException(string? message, Exception? innerException) : base(message, innerException)
        {
        }

        protected InvalidPaddingException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}

