using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Haley.Models {
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false )]
    public class DisableFormBindingAttribute : Attribute, IResourceFilter {
        bool _enableBuffering;
        public DisableFormBindingAttribute(bool enableBuffering = false) {
            // This attribute is used to disable the default form binding in ASP.NET Core.
            // It prevents the framework from automatically binding form data to model properties.
            _enableBuffering = enableBuffering;
        }
        public void OnResourceExecuted(ResourceExecutedContext context) {
            
        }

        public void OnResourceExecuting(ResourceExecutingContext context) {
            //By default, when a request is made, .Net will inspect the body and if a multi-part form data is found it will fetch it into memory or into disk.
            //This defies our whole purpose. We should not allow default processing. It also has certain limits of upto 64K temporary files creation.
            //We go ahead and disable default factories.
            var factories = context.ValueProviderFactories;
            factories.RemoveType<FormValueProviderFactory>();
            factories.RemoveType<FormFileValueProviderFactory>();
            factories.RemoveType<JQueryFormValueProviderFactory>();
            if (!_enableBuffering) return; //Dont' t enable buffering if not specified.
            var request = context.HttpContext.Request; 
            if (request != null) {
                request.EnableBuffering(); //Since we are turning of the form
                //request.Body.Position = 0; //Dont' set the body position = 0 here itself, It might prematurely read the body and causes issues.
            }
        }
    }
}
