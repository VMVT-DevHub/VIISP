

using Npgsql;
using System.Diagnostics.Eventing.Reader;
using System.Text.Json;

namespace VIISP.App;

public static class DBExec {

	public static DataResponse Login(this DataResponse dt, string connstr, string? app, bool showAk = false) {
		using var conn = new NpgsqlConnection(connstr);
		conn.Open();

		if (long.TryParse(dt.AK, out var ak)) {
			if (!showAk) dt.AK = null;


			using var cmd = new NpgsqlCommand("SELECT id,name,fname,lname,address,email,phone FROM viisp.user_login(@ak,@app,null,null,@data::jsonb)", conn);
			cmd.Parameters.Add(new("@ak", ak));
			cmd.Parameters.Add(new("@app", app));
			cmd.Parameters.Add(new("@data", JsonSerializer.Serialize(dt)));

			using var reader = cmd.ExecuteReader();

			if (reader.Read()) {
				dt.Id = reader.IsDBNull(0) ? null : reader.GetGuid(0);
				dt.Name = reader.GetString(1);
			}
			else { } //TODO: log error
		}
		else { } //TODO: log error

		return dt;
	}
}