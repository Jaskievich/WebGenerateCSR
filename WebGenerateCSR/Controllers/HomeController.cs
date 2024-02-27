using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using WebGenerateCSR.Models;

namespace WebGenerateCSR.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

		ApplicationContext db;

		public HomeController(ILogger<HomeController> logger, ApplicationContext context)
        {
            _logger = logger;
            db = context;
        }

        [HttpGet]
        public IActionResult Index()
        {
            ViewBag.Countries = db.Countries.ToList();
			return View();
        }

        [HttpPost]
        public IActionResult Index(InfoCSR infoCSR)
        {
            if (ModelState.IsValid)
            {
                KeyCSR keyCSR = GeneratorCSR.GenerateFor(infoCSR);
                infoCSR.PrivateKey = keyCSR.privateKey;
                infoCSR.ReqCSR = keyCSR.ReqCSR;
				db.InfoCSRs.Add(infoCSR);
				db.SaveChanges();
            }
            ViewBag.Countries = db.Countries.ToList();
            return View(infoCSR);
        }

		public IActionResult Result()
        {
            return View(db.InfoCSRs);
        }

    }
}