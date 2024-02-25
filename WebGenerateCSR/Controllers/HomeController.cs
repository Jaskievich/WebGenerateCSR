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
			return View();
        }

        [HttpPost]
        public IActionResult Index(InfoCSR infoCSR)
        {
            if (ModelState.IsValid)
            {
                return Content( GeneratorCSR.GenerateCSR(infoCSR) );
            }
			ViewBag.Countrys = db.Countrys.ToList();
            ViewBag.States = db.States.ToList();
			return View("Index");
        }
        //public IActionResult Privacy()
        //{
        //    return View();
        //}

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}