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

		public List<State> States { get; set; } = new();
	}

	public class State
	{
		public int Id { get; set; }

		public int CountryId {  get; set; }

		public Country? Country { get; set; }
		public string? Name { get; set; }

		List<City> cities { get; set; } = new();

	}


	public class City
	{
		public int Id { get; set; }

		public int StateId { get; set; }

		public State? State { get; set; }

		public string? Name { get; set; }
	}



	public class InfoCSR_Result
	{
		public int Id { get; set; }
		public string? DomainName { get; set; }

		public string? OrganizationName { set; get; }

		public string? OrganizationalUnit { set; get; }

		public int CountryId {  set; get; }
		public Country? Country { get; set; }

		public int StateId { get; set; }

		public State? State { get; set; }

		public int CityId {  set; get; }

		public City? CityName { set; get;}

		public string? Email { set; get; }

		public string? KeyCSR { set; get; }

	}


	public class ApplicationContext : DbContext
	{
		public DbSet<InfoCSR_Result> InfoCSR_Results { get; set; } = null!;

		public DbSet<InfoCSR> InfoCSRs { get; set; } = null!;
		public DbSet<Country> Countrys { get; set; } = null!;
		public DbSet<State> States { get; set; } = null!;
		public DbSet<City> Cities { get; set; } = null!;
		
		public ApplicationContext(DbContextOptions<ApplicationContext> options)
			: base(options)
		{
			Database.EnsureCreated();   // создаем базу данных при первом обращении
		}
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

	//	public Country Country { set; get; } = new();
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

		public string? KeyCSR { set; get; }
	}


	public class GeneratorCSR
	{
		public static string GenerateCSR(InfoCSR infoCSR)
		{

			AsymmetricCipherKeyPair pair;
			Pkcs10CertificationRequest csr;
			Asn1SignatureFactory signatureFactory;
			var random = new SecureRandom(new CryptoApiRandomGenerator());

			var ecMode = false;
			//			var values = new Dictionary<DerObjectIdentifier, string> {
			//	{X509Name.CN, "Xero Compensator"}, //domain name inside the quotes
			//    {X509Name.OU, "Infrastructure Team"},
			//	{X509Name.O, "Backbone (UK) Limited"}, //Organisation's Legal name inside the quotes
			//    {X509Name.L, "London"},
			//	{X509Name.ST, "England"},
			//	{X509Name.C, "GB"},
			//};

			var values = new Dictionary<DerObjectIdentifier, string> {
				{X509Name.CN, infoCSR.DomainName}, //domain name inside the quotes
				{X509Name.OU, infoCSR.OrganizationalUnit},
				{X509Name.O,  infoCSR.OrganizationName}, //Organisation's Legal name inside the quotes
				{X509Name.L, infoCSR.City},
				{X509Name.ST, infoCSR.State},
				{X509Name.C, infoCSR.Country},
			};
			var subjectAlternateNames = new GeneralName[] { };
			var extensions = new Dictionary<DerObjectIdentifier, Org.BouncyCastle.Asn1.X509.X509Extension>()
			{
				{X509Extensions.BasicConstraints, new Org.BouncyCastle.Asn1.X509.X509Extension(true, new DerOctetString(new BasicConstraints(false)))},
				{X509Extensions.KeyUsage, new Org.BouncyCastle.Asn1.X509.X509Extension(true, new DerOctetString(new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment | KeyUsage.NonRepudiation)))},
				{X509Extensions.ExtendedKeyUsage, new X509Extension(false, new DerOctetString(new ExtendedKeyUsage(KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth)))},
			};

			if (values[X509Name.CN].StartsWith("www.")) values[X509Name.CN] = values[X509Name.CN].Substring(4);

			if (!values[X509Name.CN].StartsWith("*.") && subjectAlternateNames.Length == 0)
				subjectAlternateNames = new GeneralName[] { new GeneralName(GeneralName.DnsName, $"www.{values[X509Name.CN]}") };

			if (subjectAlternateNames.Length > 0) extensions.Add(X509Extensions.SubjectAlternativeName, new X509Extension(false, new DerOctetString(new GeneralNames(subjectAlternateNames))));

			var subject = new X509Name(values.Keys.Reverse().ToList(), values);

			if (ecMode)
			{
				var gen = new ECKeyPairGenerator();
				//secp256r1 combined with SHA256withECDSA minimum recommended as per NIST RFC5480 to achieve 128bit encryption
				//secp384r1 combined with SHA384withECDSA message digest offers 192bit encryption
				//secp521r1 combined with SHA512withECDSA message digest offers 256bit encryption (browsers are not supporting this option right now)
				//browser cipher support can be checked via https://www.ssllabs.com/ssltest/viewMyClient.html
				var ecp = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256r1");
				gen.Init(new ECKeyGenerationParameters(new ECDomainParameters(ecp.Curve, ecp.G, ecp.N, ecp.H, ecp.GetSeed()), random));

				pair = gen.GenerateKeyPair();
				signatureFactory = new Asn1SignatureFactory("SHA256withECDSA", pair.Private);

				extensions.Add(X509Extensions.SubjectKeyIdentifier, new X509Extension(false, new DerOctetString(new SubjectKeyIdentifierStructure(pair.Public))));
				csr = new Pkcs10CertificationRequest(signatureFactory, subject, pair.Public, new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(new X509Extensions(extensions)))), pair.Private);

			}
			else
			{
				var gen = new RsaKeyPairGenerator();
				gen.Init(new KeyGenerationParameters(random, 2048));

				pair = gen.GenerateKeyPair();
				signatureFactory = new Asn1SignatureFactory("SHA256withRSA", pair.Private);

				extensions.Add(X509Extensions.SubjectKeyIdentifier, new X509Extension(false, new DerOctetString(new SubjectKeyIdentifierStructure(pair.Public))));
				csr = new Pkcs10CertificationRequest(signatureFactory, subject, pair.Public, new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(new X509Extensions(extensions)))), pair.Private);
			}

			//Convert BouncyCastle csr to .PEM file.
			var csrPem = new StringBuilder();
			var csrPemWriter = new PemWriter(new StringWriter(csrPem));
			csrPemWriter.WriteObject(csr);
			csrPemWriter.Writer.Flush();

			//Push the csr Text to a Label on a Page
			//csrPem.ToString().Dump("CSR");

			//Convert BouncyCastle Private Key to .PEM file.
			var privateKeyPem = new StringBuilder();
			var privateKeyPemWriter = new PemWriter(new StringWriter(privateKeyPem));
			privateKeyPemWriter.WriteObject(pair.Private);
			privateKeyPemWriter.Writer.Flush();

			//Push the privateKeyPem Text to a Label on a Page
			//privateKeyPem.ToString().Dump("Private Key");

			//Convert BouncyCastle Public Key to .PEM file.
			var publicKeyPem = new StringBuilder();
			var publicKeyPemWriter = new PemWriter(new StringWriter(publicKeyPem));
			publicKeyPemWriter.WriteObject(pair.Public);
			publicKeyPemWriter.Writer.Flush();

			//Push the publicKeyPem Text to a Label on a Page
			//publicKeyPem.ToString().Dump("Public Key");

			//Generate a self signed x509 certificate from above
			var notBefore = DateTime.UtcNow.Date;
			var certGenerator = new X509V3CertificateGenerator();

			certGenerator.SetSubjectDN(subject);
			certGenerator.SetIssuerDN(subject);
			certGenerator.SetNotBefore(notBefore);
			certGenerator.SetNotAfter(notBefore.AddYears(1).AddSeconds(-1));
			certGenerator.SetPublicKey(pair.Public);
			certGenerator.SetSerialNumber(BigIntegers.CreateRandomInRange(Org.BouncyCastle.Math.BigInteger.One, Org.BouncyCastle.Math.BigInteger.ValueOf(Int64.MaxValue), random));

			foreach (var extension in extensions)
				certGenerator.AddExtension(extension.Key, extension.Value.IsCritical, extension.Value.GetParsedValue());

			var bouncyCert = certGenerator.Generate(signatureFactory);

			var store = new Pkcs12Store();
			var certificateEntry = new X509CertificateEntry(bouncyCert);
			store.SetCertificateEntry(subject.ToString(), certificateEntry);
			store.SetKeyEntry(subject.ToString(), new AsymmetricKeyEntry(pair.Private), new[] { certificateEntry });

			using (var stream = new MemoryStream())
			{
				var tempPassword = "password";
				store.Save(stream, tempPassword.ToCharArray(), random);
				using (var cert = new X509Certificate2(stream.ToArray(), tempPassword, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable))
				{
					StringBuilder builder = new StringBuilder();

			//		builder.AppendLine("-----BEGIN CERTIFICATE-----");
					builder.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
			//		builder.AppendLine("-----END CERTIFICATE-----");

					//builder.ToString().Dump("Self-signed Certificate");
					return builder.ToString();
				}
			}
			return null;
		}

	}




}
