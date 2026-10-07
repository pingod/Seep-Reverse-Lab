// 最小驱动器：调用 AOB 引擎对指定文件打补丁（用于运行时验证）
// 用法: QuickPatch.exe <源exe> <目标exe>
using System;
using System.IO;

namespace IDM_Toolkit_Wpf
{
    public static class QuickPatch
    {
        public static int Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            if (args.Length < 2)
            {
                Console.WriteLine("用法: QuickPatch.exe <源exe> <目标exe>");
                return 2;
            }
            string src = args[0], dst = args[1];
            File.Copy(src, dst, true);

            int cnt = 0;
            bool ok = MainWindow.NativeBinaryPatcher.ApplyPatch(
                dst, false, new Action<string>(s => Console.WriteLine(s)), out cnt);
            Console.WriteLine("RESULT ok=" + ok + " count=" + cnt);
            Console.WriteLine("SHA256=" + Sha(dst));
            return ok ? 0 : 1;
        }

        static string Sha(string p)
        {
            using (var s = System.Security.Cryptography.SHA256.Create())
            using (var f = File.OpenRead(p))
            {
                byte[] h = s.ComputeHash(f);
                var sb = new System.Text.StringBuilder();
                foreach (byte b in h) sb.Append(b.ToString("X2"));
                return sb.ToString();
            }
        }
    }
}
