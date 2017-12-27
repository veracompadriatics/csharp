string input = "Customer ID sa jako jako puno slova, cak i preko 17";
byte[] md5 = System.Security.Cryptography.MD5.Create().ComputeHash(System.Text.Encoding.ASCII.GetBytes(input.ToLower()));
StringBuilder outputbuilder = new StringBuilder(md5.Length * 2);
for (int i = 0; i < md5.Length; i++)
  outputbuilder.Append(md5[i].ToString("x2"));
string output = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(outputbuilder.ToString())).Replace("/", "_").Replace("+", "-").Substring(0, 17);
Console.WriteLine(output);
