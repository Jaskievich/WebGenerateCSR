USE [BaseCSR]
GO
/****** Object:  Table [dbo].[Countries]    Script Date: 26.02.2024 23:09:01 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Countries](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Alpha2] [char](2) NOT NULL,
	[Name] [varchar](150) NOT NULL,
 CONSTRAINT [PK_Countries] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[InfoCSRs]    Script Date: 26.02.2024 23:09:01 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[InfoCSRs](
	[DomainName] [varchar](150) NOT NULL,
	[OrganizationName] [varchar](150) NOT NULL,
	[OrganizationalUnit] [varchar](150) NOT NULL,
	[Country] [varchar](150) NOT NULL,
	[State] [varchar](150) NOT NULL,
	[City] [varchar](150) NOT NULL,
	[Email] [varchar](150) NOT NULL,
	[ReqCSR] [varchar](max) NULL,
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[PrivateKey] [varchar](max) NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[Countries] ON 

INSERT [dbo].[Countries] ([Id], [Alpha2], [Name]) VALUES (1, N'BY', N'Belarus')
INSERT [dbo].[Countries] ([Id], [Alpha2], [Name]) VALUES (2, N'RU', N'Russian')
INSERT [dbo].[Countries] ([Id], [Alpha2], [Name]) VALUES (3, N'US', N'USA')
SET IDENTITY_INSERT [dbo].[Countries] OFF
GO
SET IDENTITY_INSERT [dbo].[InfoCSRs] ON 

INSERT [dbo].[InfoCSRs] ([DomainName], [OrganizationName], [OrganizationalUnit], [Country], [State], [City], [Email], [ReqCSR], [Id], [PrivateKey]) VALUES (N'*.mydomain.by', N'My company', N'Web, IT', N'BY', N'Minsk', N'Minsk', N'yskevich@tut.by', N'MIICrzCCAZcCAQAwbDELMAkGA1UEBhMCQlkxDjAMBgNVBAgMBU1pbnNrMQ4wDAYDVQQHDAVNaW5zazEQMA4GA1UECwwHV2ViLCBJVDETMBEGA1UECgwKTXkgY29tcGFueTEWMBQGA1UEAwwNKi5teWRvbWFpbi5ieTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJxpO+9dh89ri0QVekQQ1IY6LsAMLkznAisXh3RVGNRdSfiEjO1iFwc641Mfg8BQCnNObov9U+GgffhdopL45ukXctuLV4BOckQTd8Mhytm6FfrKZ9WvyoSOz2+BpQxauC9dJoWJBh/krsEf8bhghhpVA10gRr1gWeUvl88g8Jr3dHnHUb/gUvIe8Ca48VyFJ0li6K5f6nfFHmoSuyI1G+8+wdyoJQuGxKApL/wVDs/ljxmG/3phwwBbW0RmgDZJxZEqL1hcpz7sbjrpQCLJW/6q+W6nvE2eZVxqRUKNDqUv37cvUG7gbFAtpcr8BvSm1gcV6NACGh3Ld7oovrMc/F0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAmdxlvPSBLmHUoEli9gAEs11RYKMzr9MRZgpoyVNjbARuxFKMJyKRLLxe2/svjFsnDkBscucsq/iLsMeDU7fhta/MxB5+OpD4U9URUG+/TQ3yFkXbsh9RIbj52w/2//H8EOaNwunw9ljgwSs7QWhB2MUtJBguHLLVhPYurPNp0hKsu6jFooulswz2PnULw7qQVP/bU13F9z5YAbd2oJIXp8q3bhD0P46eTuL/0CPGpTSdOKjZuMqMmpCfPJVArp+42SnihUlcmNQ/MiH0MR9kPB7hSKhLqpIBudprVVwGGUCz/1HIxD51VOdzzlQbtrBmbucLzgR6oHP4+8jPDjjf5w==', 11, N'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnGk7712Hz2uLRBV6RBDUhjouwAwuTOcCKxeHdFUY1F1J+ISM7WIXBzrjUx+DwFAKc05ui/1T4aB9+F2ikvjm6Rdy24tXgE5yRBN3wyHK2boV+spn1a/KhI7Pb4GlDFq4L10mhYkGH+SuwR/xuGCGGlUDXSBGvWBZ5S+XzyDwmvd0ecdRv+BS8h7wJrjxXIUnSWLorl/qd8UeahK7IjUb7z7B3KglC4bEoCkv/BUOz+WPGYb/emHDAFtbRGaANknFkSovWFynPuxuOulAIslb/qr5bqe8TZ5lXGpFQo0OpS/fty9QbuBsUC2lyvwG9KbWBxXo0AIaHct3uii+sxz8XQIDAQAB')
INSERT [dbo].[InfoCSRs] ([DomainName], [OrganizationName], [OrganizationalUnit], [Country], [State], [City], [Email], [ReqCSR], [Id], [PrivateKey]) VALUES (N'*.mydomain.by', N'My company', N'Web, IT', N'BY', N'Vitebsk', N'Vitebsk', N'yskevich@tut.by', N'MIICszCCAZsCAQAwcDELMAkGA1UEBhMCQlkxEDAOBgNVBAgMB1ZpdGVic2sxEDAOBgNVBAcMB1ZpdGVic2sxEDAOBgNVBAsMB1dlYiwgSVQxEzARBgNVBAoMCk15IGNvbXBhbnkxFjAUBgNVBAMMDSoubXlkb21haW4uYnkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCOAVHj/nq6sYLI6A2cLMTsYH/vA3bCplTJRaHGSymC4GtgOKg3iyszAxHWu86XVIVOKpJqGfJ2bBHjYYmRWCNoek/Ddl8YkmZUCFc0j+KsValTdJF4de6yf6RelqL4zwdqU8FWriBbaJbPyjJbf5dZU8mXBgFcJcbhlX9CVv1mkDigutxQTAXR2neT162BCESn5aHIzE09X0POPEth32WtzixKLqYRMg4epnEsGz/OBDEEgs4snC/SgDXZP3GfkGE/ZyAamMZJilq6V4C//ElJl3IoERmc42El9GF4o0uH+bJeqS/mPC2dY++Qg4N1GXYzTKjjNR368Tmfd1x0KdtfAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAFloalMotN/dic1ZMdGzkzDJLNniVj8S8Dxo83SkZboT/v1MUxhBZtIFGVUykFZEJjZwbYFj4mgkEGKTC019Scoxy5LGrmHEtztLESXl/VJQyFlhbOAosUUXBnW2E+q4eB9Ot4ce3Y1oWNCQX7NiJOTdH9j6eW/NIJzD9OUng7CUr7NdAD/7EvDPMOIlhOhL2L6lshJnGd3M2j9oh4pEed96vVcjm9Ztf6CIMe5Zs1y3fXDrDeRpToi/zOsS3GQIbHXyD8qW14QTtyHxVfIiAPYUU8fiq+5qkHXJU/FwrYDH6W+D17g5auRAMJOzP9PGRnzfUwYUNEHINoZ2L+8Qi1o=', 12, N'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjgFR4/56urGCyOgNnCzE7GB/7wN2wqZUyUWhxkspguBrYDioN4srMwMR1rvOl1SFTiqSahnydmwR42GJkVgjaHpPw3ZfGJJmVAhXNI/irFWpU3SReHXusn+kXpai+M8HalPBVq4gW2iWz8oyW3+XWVPJlwYBXCXG4ZV/Qlb9ZpA4oLrcUEwF0dp3k9etgQhEp+WhyMxNPV9DzjxLYd9lrc4sSi6mETIOHqZxLBs/zgQxBILOLJwv0oA12T9xn5BhP2cgGpjGSYpauleAv/xJSZdyKBEZnONhJfRheKNLh/myXqkv5jwtnWPvkIODdRl2M0yo4zUd+vE5n3dcdCnbXwIDAQAB')
SET IDENTITY_INSERT [dbo].[InfoCSRs] OFF
GO
