using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.OpenSsl;
using System.ComponentModel.DataAnnotations;
using X509Extension = Org.BouncyCastle.Asn1.X509.X509Extension;
using Microsoft.EntityFrameworkCore;

namespace WebGenerateCSR.Models
{

	public class Country
	{
		public int Id { get; set; }
		public string Name { get; set; } // наименование страны
		public string Alpha2 { get; set; } // наименование страны

	}


	public class ApplicationContext : DbContext
	{
		
		public DbSet<InfoCSR> InfoCSRs { get; set; } = null!;
		public DbSet<Country> Countries { get; set; } = null!;
			
		public ApplicationContext(DbContextOptions<ApplicationContext> options)
			: base(options)
		{
			Database.EnsureCreated();   // создаем базу данных при первом обращении
		}
	}

	public class KeyCSR
	{
		public string publicKey { set; get; } = "";
		public string privateKey { set; get; } = "";
		public string ReqCSR { set; get; } = "";

	}
	public class InfoCSR
	{
		public int Id { set; get; }
		[Display(Name = "Введите домен")]
		[Required(ErrorMessage = "Введите домен")]
		public string DomainName { set; get; }

		[Display(Name = "Введите организацию")]
		[Required(ErrorMessage = "Введите организацию")]
		public string OrganizationName { set; get; }

		[Display(Name = "Введите отдел")]
		[Required(ErrorMessage = "Введите отдел")]
		public string OrganizationalUnit { set; get; }

		[Display(Name = "Выберите страну")]

		public string Country { set; get; }

		[Display(Name = "Введите область")]
		[Required(ErrorMessage = "Введите область")]
		public string State { set; get; }

		[Display(Name = "Введите город")]
		[Required(ErrorMessage = "Введите город")]
		public string City { set; get; }

		[Display(Name = "Введите почтовый адресс")]
		[Required(ErrorMessage = "Введите почтовый адресс")]
		public string Email { set; get; }

		public string? ReqCSR { set; get; } 

		public string? PrivateKey { set; get; }
    }


	public class GeneratorCSR
	{
		private static AsymmetricCipherKeyPair GenerateKeyPair()
		{
			// Generate private/public key pair
			RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
			KeyGenerationParameters keyParams = new KeyGenerationParameters(new SecureRandom(), 2048);
			generator.Init(keyParams);
			return generator.GenerateKeyPair();
		}

		private static string RemovePemHeaderFooter(string input)
		{
			var headerFooterList = new List<string>()
			{
				"-----BEGIN CERTIFICATE REQUEST-----",
				"-----END CERTIFICATE REQUEST-----",
				"-----BEGIN PUBLIC KEY-----",
				"-----END PUBLIC KEY-----",
				"-----BEGIN RSA PRIVATE KEY-----",
				"-----END RSA PRIVATE KEY-----"

			};

			string trimmed = input;
			foreach (var hf in headerFooterList)
			{
				trimmed = trimmed.Replace(hf, string.Empty);
			}

			return trimmed.Replace("\r\n", string.Empty);
		}

		private static string GenerateCertRequest(InfoCSR infoCSR , AsymmetricCipherKeyPair keyPair)
		{
			var values = new Dictionary<DerObjectIdentifier, string> {
				
				{X509Name.CN, infoCSR.DomainName}, //domain name inside the quotes
				{X509Name.O, infoCSR.OrganizationName}, //Organisation\'s Legal name inside the quotes
				{X509Name.OU, infoCSR.OrganizationalUnit},
				{X509Name.L, infoCSR.City},
				{X509Name.ST, infoCSR.State},
				{X509Name.C, infoCSR.Country},
			};

			var subject = new X509Name(values.Keys.Reverse().ToList(), values);
			var csr = new Pkcs10CertificationRequest(new Asn1SignatureFactory("SHA256withRSA", keyPair.Private), subject,
			keyPair.Public, null, keyPair.Private);

			//Convert BouncyCastle csr to PEM format
			var csrPem = new StringBuilder();
			var csrPemWriter = new PemWriter(new StringWriter(csrPem));
			csrPemWriter.WriteObject(csr);
			csrPemWriter.Writer.Flush();
			return RemovePemHeaderFooter(csrPem.ToString());
		}

		public static KeyCSR GenerateFor(InfoCSR infoCSR)
		{
			KeyCSR keyCSR = new KeyCSR();
			var keyPair = GenerateKeyPair();
			var keyPem = new StringBuilder();
			var keyPemWriter = new PemWriter(new StringWriter(keyPem));
			keyPemWriter.WriteObject(keyPair.Public);
			keyPemWriter.Writer.Flush();

			keyCSR.publicKey = RemovePemHeaderFooter(keyPem.ToString());

			var keyPemPr = new StringBuilder();
			var keyPemWriterPr = new PemWriter(new StringWriter(keyPemPr));
			keyPemWriterPr.WriteObject(keyPair.Private);
			keyPemWriterPr.Writer.Flush();

			keyCSR.privateKey = RemovePemHeaderFooter(keyPem.ToString());

			keyCSR.ReqCSR = GenerateCertRequest(infoCSR, keyPair);

			return keyCSR;
		}
	}




}
