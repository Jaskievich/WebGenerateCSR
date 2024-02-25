using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using WebGenerateCSR.Models;
using static WebGenerateCSR.Models.GeneratorCSR;

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
            ViewBag.Countrys = db.Countrys.ToList();
			ViewBag.States = db.States.ToList();
			ViewBag.Cities = db.Cities.ToList();
			return View();
        }

        [HttpPost]
        public IActionResult Index(InfoCSR infoCSR)
        {
            if (ModelState.IsValid)
            {
                infoCSR.KeyCSR = GeneratorCSR.GenerateCSR(infoCSR);
                db.InfoCSRs.Add(infoCSR);
				db.SaveChanges();
				return View("Result",db.InfoCSRs);
            }
			return Index();
        }

        public IActionResult Result()
        {
            return View(db.InfoCSRs);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}