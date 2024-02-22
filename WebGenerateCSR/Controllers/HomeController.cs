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
            var countres = db.Countrys.ToList();
			return View(countres);
        }

        [HttpPost]
        public string Index(InfoCSR infoCSR)
        {
            return GeneratorCSR.GenerateCSR(infoCSR);
            //	return View();
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