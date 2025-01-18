using Hangfire;
using Hangfire.Dashboard.BasicAuthorization;
using Hangfire.Dashboard;
using Microsoft.AspNetCore.Builder;
using System.Diagnostics.CodeAnalysis;
using Hangfire.Redis.StackExchange;
using Microsoft.Extensions.DependencyInjection;
using ProSoft.DnsBL.Api.BackgroundServices.SchedulerJobs;

namespace ProSoft.DnsBL.Api.BackgroundServices.DependencyInjection;

[ExcludeFromCodeCoverage]
public static class DependencyResolver
{
	public static IServiceCollection AddAndConfigureBackgroundServices(this IServiceCollection services)
	{
		services
			.AddHangfire
			(
				config => config
				          .UseSimpleAssemblyNameTypeSerializer()
				          .UseRecommendedSerializerSettings()
				          .UseStorage(UseRedisStorage())
			)
			.AddHangfireServer(options => options.ServerName = Environment.MachineName)
			.AddHttpClient()
			;

		//services.AddScoped<I..., ...>();

		return services;
	}

	public static IApplicationBuilder UseBackgroundServices(this IApplicationBuilder app)
	{
		app.UseHangfireDashboard("/hangfire", CreateDashboardOptions());

		RecurringJob.AddOrUpdate<BlacklistDataCollectorJob>
		(
			BlacklistDataCollectorJob.ServiceName,
			job => job.Process(CancellationToken.None),
			BlacklistDataCollectorJob.CronSchedule
		);

		return app;
	}

	private static DashboardOptions CreateDashboardOptions()
	{
		return new DashboardOptions
		{
			AppPath = null,
			Authorization = CreateHangfireAuthenticationList()
		};
	}

	private static List<IDashboardAuthorizationFilter> CreateHangfireAuthenticationList()
	{
#if DEBUG
		return new List<IDashboardAuthorizationFilter>();
#endif
		var authorizationList = new List<IDashboardAuthorizationFilter>
		{
			new BasicAuthAuthorizationFilter
			(
				new BasicAuthAuthorizationFilterOptions
				{
					RequireSsl = true,
					SslRedirect = true,
					LoginCaseSensitive = true,
					Users =
					[
						new BasicAuthAuthorizationUser
						{
							Login = "hangfire",
							PasswordClear = "Geheim123#"
						}
					]
				}
			)
		};

		return authorizationList;
	}

	private static RedisStorage UseRedisStorage()
	{
		return new RedisStorage
		(
			"10.215.10.50:6379",
			new RedisStorageOptions
			{
				Prefix = "_hangfire",
			}
		);
	}
}
