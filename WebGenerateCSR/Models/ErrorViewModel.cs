
using Microsoft.EntityFrameworkCore;

namespace WebGenerateCSR.Models
{
	public class ErrorViewModel
	{
		public string? RequestId { get; set; }

		public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
	}


	
}