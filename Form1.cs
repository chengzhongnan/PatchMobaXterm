using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace PatchMobaXterm
{
  public partial class Form1 : Form
  {
    public Form1()
    {
      InitializeComponent();
    }

    private void button1_Click(object sender, EventArgs e)
    {
      using (OpenFileDialog openFileDialog = new OpenFileDialog())
      {
        // 配置打开文件对话框
        openFileDialog.Filter = "MobaXterm|MobaXterm.exe|可执行文件|*.exe|所有文件|*.*";
        openFileDialog.Title = "请选择 MobaXterm.exe 文件";
        openFileDialog.FileName = "MobaXterm.exe";

        // 显示对话框
        if (openFileDialog.ShowDialog() == DialogResult.OK)
        {
          textBox1.Text = openFileDialog.FileName;
        }
      }
    }

    static List<long> FindPatternInFile(string filePath, byte?[] pattern)
    {
      List<long> matches = new List<long>();

      try
      {
        using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
        using (BinaryReader reader = new BinaryReader(fs))
        {
          byte[] buffer = new byte[fs.Length];
          reader.Read(buffer, 0, buffer.Length);

          for (long i = 0; i < buffer.Length - pattern.Length; i++)
          {
            bool isMatch = true;

            for (int j = 0; j < pattern.Length; j++)
            {
              if (pattern[j].HasValue && buffer[i + j] != pattern[j].Value)
              {
                isMatch = false;
                break;
              }
            }

            if (isMatch)
            {
              matches.Add(i);
            }
          }
        }
      }
      catch (Exception ex)
      {
        MessageBox.Show($"Error: {ex.Message}");
        throw ex;
      }

      return matches;
    }

    /// <summary>
    /// 从文件中指定偏移量读取字节数组
    /// </summary>
    /// <param name="filePath">文件路径</param>
    /// <param name="offset">读取的起始偏移量</param>
    /// <param name="length">要读取的字节数</param>
    /// <returns>读取的字节数组</returns>
    public static byte[] ReadBytesFromFile(string filePath, long offset, int length)
    {
      byte[] buffer = new byte[length];
      using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
      {
        if (offset >= fs.Length)
        {
          throw new ArgumentOutOfRangeException("Offset is beyond the file length.");
        }

        fs.Seek(offset, SeekOrigin.Begin);
        fs.Read(buffer, 0, length);
      }
      return buffer;
    }

    /// <summary>
    /// 写入字节数组到文件的指定偏移量
    /// </summary>
    /// <param name="filePath">文件路径</param>
    /// <param name="offset">写入的起始偏移量</param>
    /// <param name="data">要写入的字节数组</param>
    public static void WriteBytesToFile(string filePath, long offset, byte[] data)
    {
      try
      {
        using (FileStream fs = new FileStream(filePath, FileMode.OpenOrCreate, FileAccess.Write))
        {
          fs.Seek(offset, SeekOrigin.Begin);
          fs.Write(data, 0, data.Length);
        }
      }
      catch (UnauthorizedAccessException)
      {
        MessageBox.Show("无法写入目标文件，请使用管理员权限启动本程序，再运行破解！");
        Application.Exit();
      }
    }

    private void PatchMobaXterm(string fileName)
    {
      // 第一个Patch数组
      byte?[] pattern1 = new byte?[]
      {
        0x9B,                    // wait
        0x8B, 0x45, 0xFC,       // mov eax, dword ptr [ebp-4]
        0xC7, 0x80, null, null, null, null, null, null, null, null,  // mov dword ptr [eax+E3C], 0C ，破解是将这里的0C改成一个很大的数值
        0x8B, 0x45, 0xFC,       // mov eax, dword ptr [ebp-4]
        0xC6, 0x80, null, null, null, null, null,  // mov byte ptr [eax+F04], 0
        0x8B, 0x45, 0xFC,       // mov eax, dword ptr [ebp-4]
        0xC6, 0x80, null, null, null, null, null,  // mov byte ptr [eax+F0D], 0
        0xB2, 0x01              // mov dl, 1
      };

      // 第二个Patch数组
      byte?[] pattern2 = new byte?[]
      {
        0xA1, null, null, null, null,    // mov eax, dword ptr [不同地址]
        0x8B, 0x00,                      // mov eax, dword ptr [eax]
        0x83, 0xB8, null, null, null, null, null,  // cmp dword ptr [eax+不同偏移], 0
        0x7E, 0x33,                      // jle short xxxx
        0xA1, null, null, null, null,    // mov eax, dword ptr [不同地址]
        0x8B, 0x00,                      // mov eax, dword ptr [eax]
        0x83, 0xB8, null, null, null, null, null,  // cmp dword ptr [eax+F8C], 0
        0x75, 0x23,                      // jnz short xxxx
        0x83, 0x7D, 0xC0, 0x06,         // cmp dword ptr [ebp-40], 6
        0x7C, null,                      // jl short xxxx ， 破解是将这里的跳转改成强制跳转
        0x68, null, null, null, null,   // push 41040
        0xB9, null, null, null, null,   // mov ecx, null
        0xBA, null, null, null, null,   // mov edx, null
        0xA1, null, null, null, null,   // mov eax, dword ptr [null]
        0x8B, 0x00,                     // mov eax, dword ptr [eax]
        0xE8, null, null, null, null,   // call null
        0xEB, null                      // jmp short null
      };

      // 第三个数组
      byte?[] pattern3 = new byte?[]
      {
           0x8B, 0x46, 0x08,                   // mov     eax, dword ptr [esi+8]
           0xBA, null, null, null, null,       // mov     edx, 00997CF4
           0xE8, null, null, null, null,       // call    00405620
           0x75, 0x0F,                         // jnz     short 00997624
           0x83, 0x7D, null, 0x06,             // cmp     dword ptr [ebp-2C], 6 , 破解是将这行和下行的判断给直接NOP掉
           0x0F, 0x9D, 0xC3,                   // setge   bl
           0xFF, 0x45, null,                   // inc     dword ptr [ebp-2C]
           0xE9, null, null, null, null        // jmp     00997740
      };

      // 查找第一个Patch点
      List<long> offsets1 = FindPatternInFile(fileName, pattern1);

      if (offsets1.Count != 1)
      {
        MessageBox.Show(offsets1.Count == 0
            ? "无法找到第一个破解点，请确认你选择的是MobaXterm主程序！"
            : "找到多个第一个破解点，请检查文件版本是否匹配！");
        return;
      }

      // 第一个Patch逻辑
      long offset1 = offsets1[0];
      int index1 = 10;

      var readBytes1 = ReadBytesFromFile(fileName, offset1 + index1, 4);
      if (readBytes1[0] != 0xC || readBytes1[1] != 0x0 || readBytes1[2] != 0x0 || readBytes1[3] != 0x0)
      {
        if (MessageBox.Show("当前版本疑似已经破解，是否继续破解？", "提示", MessageBoxButtons.YesNo) != DialogResult.Yes)
        {
          return;
        }
      }

      WriteBytesToFile(fileName, offset1 + index1, new byte[] { 0xFF, 0xFF });

      // 查找第二个Patch点
      List<long> offsets2 = FindPatternInFile(fileName, pattern2);

      if (offsets2.Count != 1)
      {
        MessageBox.Show(offsets2.Count == 0
            ? "无法找到第二个破解点，请确认你选择的是MobaXterm主程序！"
            : "找到多个第二个破解点，请检查文件版本是否匹配！");
        return;
      }

      // 第二个Patch逻辑
      long offset2 = offsets2[0];
      int index2 = 36; // 偏移量从Pattern中 jl 的位置开始

      var readBytes2 = ReadBytesFromFile(fileName, offset2 + index2, 2);
      if (readBytes2[0] == 0xEB)
      {
        if (MessageBox.Show("当前版本疑似已经破解，是否继续破解？", "提示", MessageBoxButtons.YesNo) != DialogResult.Yes)
        {
          return;
        }
      }

      WriteBytesToFile(fileName, offset2 + index2, new byte[] { 0xEB });

      List<long> offsets3 = FindPatternInFile(fileName, pattern3);

      if (offsets3.Count <= 0 || offsets3.Count >= 20)
      {
        MessageBox.Show("无法找到第三个破解点，请确认你选择的是MobaXterm主程序！");
        return;
      }

      foreach(var offset in offsets3)
      {
        WriteBytesToFile(fileName, offset + 15, new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 });
      }

      // 成功提示
      MessageBox.Show("MobaXterm已经破解成功，现在可以正常使用。");
    }

    public static bool BackupFile(string sourceFilePath)
    {
      try
      {
        // 检查源文件是否存在
        if (!File.Exists(sourceFilePath))
        {
          return false;
        }

        // 获取文件信息
        FileInfo fileInfo = new FileInfo(sourceFilePath);
        string directory = fileInfo.DirectoryName;
        string fileName = Path.GetFileNameWithoutExtension(sourceFilePath);
        string extension = Path.GetExtension(sourceFilePath);

        // 构造备份文件名
        string backupFileName = $"{fileName}_bak{extension}";
        string backupFilePath = Path.Combine(directory, backupFileName);

        // 复制文件
        File.Copy(sourceFilePath, backupFilePath, true);
        return true;
      }
      catch (Exception ex)
      {
        Console.WriteLine($"备份文件时发生错误: {ex.Message}");
        return false;
      }
    }

    private void button2_Click(object sender, EventArgs e)
    {
      if (string.IsNullOrEmpty(textBox1.Text))
      {
        return;
      }

      if (checkBox1.Checked)
      {
        BackupFile(textBox1.Text);
      }
      PatchMobaXterm(textBox1.Text);
    }
  }
}
