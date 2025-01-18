using System.Diagnostics.CodeAnalysis;

namespace ProSoft.DnsBL.Api.BackgroundServices;

public abstract class BaseJob
{
	public static string ServiceName;

	public static string CronSchedule;

	public abstract Task Process(CancellationToken cancellationToken);
}
