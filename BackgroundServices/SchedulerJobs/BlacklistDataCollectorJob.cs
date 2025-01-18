using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Microsoft.Extensions.Logging;
using ProSoft.DnsBL.Api.Models;

namespace ProSoft.DnsBL.Api.BackgroundServices.SchedulerJobs;

public sealed class BlacklistDataCollectorJob : BaseJob, IDisposable
{
	private readonly ILogger<BlacklistDataCollectorJob> _logger;
	private readonly IHttpClientFactory _httpClientFactory;
	public new static string ServiceName => "Blacklist Data Collector";

	public new static string CronSchedule => "0 5 * * *";

	public BlacklistDataCollectorJob(ILogger<BlacklistDataCollectorJob> logger, IHttpClientFactory httpClientFactory)
	{
		_logger = logger;
		_httpClientFactory = httpClientFactory;
	}

	public override async Task Process(CancellationToken cancellationToken)
	{
		try
		{
			_logger.LogInformation($"Start background job for {ServiceName}");

			var urlList = new HashSet<string>();
			var blocklists = this.GetBlackLists();

			foreach (var blocklist in blocklists)
			{
				var urlCounter = 0;
				var watch = new Stopwatch();
				watch.Start();

				using (var httpClient = _httpClientFactory.CreateClient())
				{
					var response = await httpClient.GetAsync(blocklist.Url, cancellationToken);
					response.EnsureSuccessStatusCode();

					await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
					using var reader = new StreamReader(stream);

					while (!reader.EndOfStream)
					{
						var line = await reader.ReadLineAsync(cancellationToken);

						if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#") || line.StartsWith("!"))
							continue;

						switch (blocklist.BlocklistType)
						{
							case BlocklistType.Adguard:
								if (line.StartsWith("||"))
								{
									urlList.Add(line);
									urlCounter++;
								}
								break;

							case BlocklistType.DomainOnly:
								urlList.Add($"||{line}^");
								urlCounter++;
								break;

							case BlocklistType.IpSetter:
								if (line.StartsWith("127.0.0.1"))
								{
									var urlString = line.Replace("127.0.0.1 ", string.Empty);
									urlList.Add($"||{urlString}^");
									urlCounter++;
								}
								else if (line.StartsWith("0.0.0.0"))
								{
									var urlString = line.Replace("0.0.0.0 ", string.Empty);
									urlList.Add($"||{urlString}^");
									urlCounter++;
								}

								break;
						}
					}
				}
				
				watch.Stop();

				_logger.LogInformation($"{urlCounter} urls collected in {watch.ElapsedMilliseconds} ms.");
			}

			var stringBuilder = new StringBuilder();
			foreach (var item in urlList)
			{
				stringBuilder.AppendLine(item);
			}

			var test = stringBuilder.ToString();

			await File.WriteAllTextAsync(@"T:\UrlList.txt", test, Encoding.UTF8, cancellationToken);
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, $"Error during executing background job for {ServiceName}");
		}
		finally
		{
			_logger.LogInformation($"Finished background job for {ServiceName}");
		}
	}

	private List<BlockList> GetBlackLists()
	{
		var blockLists = new List<BlockList>
		{
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_12.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_55.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_56.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://phishing.army/download/phishing_army_blocklist_extended.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_50.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_54.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/crypto" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/gambling" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/DomainSquatting1" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/DomainSquatting2" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Fake-Science" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/SupportingRussia" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/proxies" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://raw.githubusercontent.com/RPiList/specials/refs/heads/master/Blocklisten/malware" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://raw.githubusercontent.com/RPiList/specials/refs/heads/master/Blocklisten/Corona-Blocklist" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://raw.githubusercontent.com/RPiList/specials/refs/heads/master/Blocklisten/DatingSites" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://raw.githubusercontent.com/RPiList/specials/refs/heads/master/Blocklisten/notserious" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.Adguard, Url = "https://raw.githubusercontent.com/RPiList/specials/refs/heads/master/Blocklisten/spam.mails" },

			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.DomainOnly, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.DomainOnly, Url = "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/MS-Office-Telemetry" },

			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.IpSetter, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.IpSetter, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_9.txt" },
			new() { SystemId = Guid.NewGuid(), Id = 1, Title = "", BlocklistType = BlocklistType.IpSetter, Url = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_23.txt" },
		};

		return blockLists;
	}

	#region IDisposable Interface Implementation

	private bool _disposed;

	/// <summary>
	/// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
	/// </summary>
	/// <autogeneratedoc />
	[ExcludeFromCodeCoverage]
	public void Dispose()
	{
		this.Dispose(true);
		GC.SuppressFinalize(this);
	}

	/// <summary>
	/// Releases unmanaged and - optionally - managed resources.
	/// </summary>
	/// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
	/// <autogeneratedoc />
	[ExcludeFromCodeCoverage]
	private void Dispose(bool disposing)
	{
		if (!_disposed && disposing)
		{
			// Disposing Logic
		}

		_disposed = true;
	}

	/// <summary>
	/// Finalizes an instance of the <see cref="BlacklistDataCollectorJob"/> class.
	/// </summary>
	/// <autogeneratedoc />
	[ExcludeFromCodeCoverage]
	~BlacklistDataCollectorJob()
	{
		this.Dispose(false);
	}

	#endregion
}
