// Gate 8's .NET serializer for the fixture story (emit.py runs it, built by
// the test): for each variable name given, the value in this process's
// environment as System.Text.Json serializes a string with its default
// encoder, then NUL, then the SHA-256 of the value in hex, then NUL.
// Nothing else is written, and no error holds a value.
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public static class Emit
{
    public static int Main(string[] names)
    {
        using Stream stdout = Console.OpenStandardOutput();
        foreach (string name in names)
        {
            string value = Environment.GetEnvironmentVariable(name);
            if (value == null)
            {
                Console.Error.WriteLine("Emit.cs: a variable is not set");
                return 1;
            }
            string json = JsonSerializer.Serialize(value);
            string digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
            byte[] record = Encoding.UTF8.GetBytes(json + "\0" + digest + "\0");
            stdout.Write(record, 0, record.Length);
        }
        stdout.Flush();
        return 0;
    }
}
