#NRII open authentication provider of OWIN#
##Installation##
Use following command to install each package in your project
`Install-Package Microsoft.Owin.Security.NRII`
##Getting Started##
Before you use these package,i assume you already created your own application in [http://nrii.org.cn/]

1. Create an asp.net 5 web application ,and select 'MVC' template.do not change authentication setting.
2. Install these providers
3. Open `Startup.Auth.cs` file,add following namespaces
	`Microsoft.Owin.Security.NRII`
4. add following code section with your 'appId' and 'secretId'.
	`app.UseNRIIAuthentication("YOUR APP ID", "YOUR SECRET ID");`
	or for test
	`app.UseNRIIAuthenticationTest("YOUR APP ID", "YOUR SECRET ID");`
	
5. Try to run your application with the domain address you designated in management center of each open platform