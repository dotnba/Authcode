using System;
using System.ComponentModel;
using System.Text;
using Sudo.Common;

/// <summary>
/// Date:2020/03/29
/// Author:dotnba
/// </summary>
namespace Sudo.Utils
{
    /// <summary>
    /// C#版本 Discuz Authcode函数。
    /// </summary>
    public class Authcode
    {
        #region 字段及属性
        /// <summary>
        /// 此属性的值表示自 0001 年 1 月 1 日午夜 12:00:00 以来已经过的时间的以 100 毫微秒为间隔的间隔数。
        /// 从 0000年00月00日00：00：00-1970年01月01日00：00：00的刻度值(毫秒)
        /// 1970 × 365 × 24 × 60 × 60 × 1000 × 10000 大概等于 621355968000000000
        /// </summary>
        public const long FROM_1970101 = 621355968000000000;
        /// <summary>
        /// 缺省过期时间(秒)
        /// </summary>
        public const int DEFAULT_EXPIRY = 7200;
        /// <summary>
        /// 默认分隔符
        /// </summary>
        public const char DEFAULT_SEPARATOR = '\t';
        /// <summary>
        /// 默认密钥
        /// </summary>
        private const string DEFAULT_KEY = "vOmj6hAZB3548vIP";
        /// <summary>
        /// 字符集
        /// </summary>
        private const string CHAR_SET = "GBK";
        /// <summary>
        /// 编码
        /// </summary>
        private Encoding _encoding;
        /// <summary>
        /// 过期时间(秒)
        /// </summary>
        private int _expiry = DEFAULT_EXPIRY;
        /// <summary>
        /// 密钥
        /// </summary>
        private string _key = DEFAULT_KEY;
        /// <summary>
        /// 密钥
        /// </summary>
        private string Key
        {
            get => _key;
            set => _key = string.IsNullOrWhiteSpace(value) || value.Length < 16 ? DEFAULT_KEY : value;
        }
        /// <summary>
        /// 过期时间
        /// </summary>
        private int Expiry
        {
            get => _expiry;
            set => _expiry = value < 0 ? DEFAULT_EXPIRY : value;
        }
        #endregion
        #region 构造函数 
        /// <summary>
        /// 无参数构造函数
        /// </summary>
        public Authcode()
        {
            InitializeEncoding();
        }
        /// <summary>
        /// 构造函数
        /// <param name="key">密钥</param>
        /// <param name="expiry">过期时间(秒)</param>
        /// </summary>
        public Authcode(string key,int expiry = DEFAULT_EXPIRY) :this()
        {
            Key = key;
            Expiry = expiry;
        }
        /// <summary>
        /// 初始化编码字符集
        /// </summary>
        private void InitializeEncoding()
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            _encoding = Encoding.GetEncoding(CHAR_SET);
        }
        #endregion
        #region 对外公开方法
        /// <summary>
        /// 使用 authcode 方法对字符串加密
        /// </summary>
        /// <param name="source">原始字符串</param>
        /// <returns>加密结果</returns>
        public AuthcodeResult Encode(string source)
        {
            return DiscuzAuthcode(source, Key, AuthcodeMode.Encode, Expiry);

        }
        /// <summary>
        /// 使用 Discuz authcode 方法对字符串解密
        /// </summary>
        /// <param name="source">原始字符串</param>
        /// <returns>解密结果</returns>
        public AuthcodeResult Decode(string source)
        {
            return DiscuzAuthcode(source, Key, AuthcodeMode.Decode, Expiry);

        }
        /// <summary>
        /// 根据加密字符串获取指定位置的值
        /// </summary>
        /// <param name="encrypted">Encrypted string</param>
        /// <param name="pos">位置</param>
        /// <param name="separator">分隔符</param>
        /// <returns></returns>
        public AuthcodeResult GetValue(string encrypted, int pos = 0,char separator = DEFAULT_SEPARATOR)
        {
            if (string.IsNullOrWhiteSpace(encrypted)) return GetAuthcodeResult(AuthcodeError.Empty);
            encrypted = encrypted.Replace(" ", "+");
            AuthcodeResult source = Decode(encrypted);
            if (source.Code == AuthcodeError.Ok)
            {
                string[] original = source.Result.Split(new char[] { separator });
                if (original.Length < pos + 1) return null;
                return GetAuthcodeResult(AuthcodeError.Ok,original[pos]);
            }
            return source;
        }
        #endregion
        #region 私有方法
        /// <summary>
        /// 从字符串的指定位置截取指定长度的子字符串
        /// </summary>
        /// <param name="str">原字符串</param>
        /// <param name="startIndex">子字符串的起始位置</param>
        /// <param name="length">子字符串的长度</param>
        /// <returns>子字符串</returns>
        private string CutString(string str, int startIndex, int length)
        {
            if (startIndex >= 0)
            {
                if (length < 0)
                {
                    length *= -1;
                    if (startIndex - length < 0)
                    {
                        length = startIndex;
                        startIndex = 0;
                    }
                    else
                    {
                        startIndex -= length;
                    }
                }

                if (startIndex > str.Length)
                {
                    return "";
                }
            }
            else
            {
                if (length < 0)
                {
                    return "";
                }
                else
                {
                    if (length + startIndex > 0)
                    {
                        length += startIndex;
                        startIndex = 0;
                    }
                    else
                    {
                        return "";
                    }
                }
            }

            if (str.Length - startIndex < length)
            {
                length = str.Length - startIndex;
            }

            return str.Substring(startIndex, length);
        }

        /// <summary>
        /// 从字符串的指定位置开始截取到字符串结尾的了符串
        /// </summary>
        /// <param name="str">原字符串</param>
        /// <param name="startIndex">子字符串的起始位置</param>
        /// <returns>子字符串</returns>
        private string CutString(string str, int startIndex)
        {
            return CutString(str, startIndex, str.Length);
        }

        /// <summary>
        /// MD5函数
        /// </summary>
        /// <param name="str">原始字符串</param>
        /// <returns>MD5结果</returns>
        private string MD5(string str)
        {
            byte[] b = _encoding.GetBytes(str);
            b = new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(b);
            string ret = "";
            for (int i = 0; i < b.Length; i++)
            {
                ret += b[i].ToString("x").PadLeft(2, '0');
            }
            return ret;
        }

        /// <summary>
        /// 用于 RC4 处理密码
        /// </summary>
        /// <param name="pass">密码字串</param>
        /// <param name="kLen">密钥长度，一般为 256</param>
        /// <returns></returns>
        private Byte[] GetKey(Byte[] pass, Int32 kLen)
        {
            Byte[] mBox = new Byte[kLen];
            for (Int64 i = 0; i < kLen; i++)
            {
                mBox[i] = (Byte)i;
            }
            Int64 j = 0;
            for (Int64 i = 0; i < kLen; i++)
            {
                j = (j + mBox[i] + pass[i % pass.Length]) % kLen;
                Byte temp = mBox[i];
                mBox[i] = mBox[j];
                mBox[j] = temp;
            }
            return mBox;
        }

        /// <summary>
        /// 生成随机字符
        /// </summary>
        /// <param name="lens">随机字符长度</param>
        /// <returns>随机字符</returns>
        private string RandomString(int lens)
        {
            string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
            StringBuilder sb = new StringBuilder();
            Random random = new Random();
            for (int i = 0, charLens = validChars.Length; i < lens; i++)
            {
                sb.Append(validChars[random.Next(charLens)]);
            }
            return sb.ToString();
        }
        /// <summary>
        /// 将AuthcodeError值转化为AuthcodeResult
        /// </summary>
        /// <param name="code">AuthcodeError类型值</param>
        /// <param name="result">AuthcodeResult的Result值</param>
        /// <returns></returns>
        private AuthcodeResult GetAuthcodeResult(AuthcodeError code, string result = "")
        {
            return new AuthcodeResult()
            {
                Code = code,
                Result = string.IsNullOrWhiteSpace(result) ? code.GetDescription() : result
            };
        }
        /// <summary>
        /// 使用 变形的 rc4 编码方法对字符串进行加密或者解密
        /// </summary>
        /// <param name="source">原始字符串</param>
        /// <param name="key">密钥</param>
        /// <param name="operation">操作 加密还是解密</param>
        /// <param name="expiry">密文有效期, 加密时候有效， 单 位 秒，0 为永久有效</param>
        /// <returns>加密或者解密后的字符串</returns>
        private AuthcodeResult DiscuzAuthcode(string source, string key, AuthcodeMode operation, int expiry = 0)
        {
            if (string.IsNullOrWhiteSpace(source) || string.IsNullOrWhiteSpace(key))
                return GetAuthcodeResult(AuthcodeError.Empty);
            int ckey_length = 4;
            string keya, keyb, keyc, cryptkey, result;

            key = MD5(key);
            keya = MD5(CutString(key, 0, 16));
            keyb = MD5(CutString(key, 16, 16));
            keyc = ckey_length > 0 ? (operation == AuthcodeMode.Decode ? CutString(source, 0, ckey_length) : RandomString(ckey_length)) : "";

            cryptkey = keya + MD5(keya + keyc);

            if (operation == AuthcodeMode.Decode)
            {
                byte[] temp;
                try
                {
                    temp = System.Convert.FromBase64String(CutString(source, ckey_length));
                }
                catch
                {
                    try
                    {
                        temp = System.Convert.FromBase64String(CutString(source + "=", ckey_length));
                    }
                    catch
                    {
                        try
                        {
                            temp = System.Convert.FromBase64String(CutString(source + "==", ckey_length));
                        }
                        catch
                        {
                            return GetAuthcodeResult(AuthcodeError.Error);
                        }
                    }
                }
                result = _encoding.GetString(RC4(temp, cryptkey));
                long timestamp = long.Parse(CutString(result, 0, 10));
                if ((timestamp == 0 || timestamp - UnixTimestamp() > 0) && CutString(result, 10, 16) == CutString(MD5(CutString(result, 26) + keyb), 0, 16))
                {
                    return GetAuthcodeResult(AuthcodeError.Ok, CutString(result, 26));
                }
                else
                {
                    return GetAuthcodeResult(AuthcodeError.Expriry);
                }
            }
            else
            {
                source = (expiry == 0 ? "0000000000" : (expiry + UnixTimestamp()).ToString()) + CutString(MD5(source + keyb), 0, 16) + source;
                byte[] temp = RC4(_encoding.GetBytes(source), cryptkey);
                return GetAuthcodeResult(AuthcodeError.Ok, keyc + System.Convert.ToBase64String(temp));
            }
        }
        /// <summary>
        /// RC4 原始算法
        /// </summary>
        /// <param name="input">原始字串数组</param>
        /// <param name="pass">密钥</param>
        /// <returns>处理后的字串数组</returns>
        private Byte[] RC4(Byte[] input, String pass)
        {
            if (input == null || pass == null) return null;

            byte[] output = new Byte[input.Length];
            byte[] mBox = GetKey(_encoding.GetBytes(pass), 256);

            // 加密
            Int64 i = 0;
            Int64 j = 0;
            for (Int64 offset = 0; offset < input.Length; offset++)
            {
                i = (i + 1) % mBox.Length;
                j = (j + mBox[i]) % mBox.Length;
                Byte temp = mBox[i];
                mBox[i] = mBox[j];
                mBox[j] = temp;
                Byte a = input[offset];
                // mBox[j] 一定比 mBox.Length 小，不需要再取模
                Byte b = mBox[(mBox[i] + mBox[j]) % mBox.Length];
                output[offset] = (Byte)((Int32)a ^ (Int32)b);
            }

            return output;
        }

        private long UnixTimestamp()
        {
            TimeSpan toNow = new TimeSpan(DateTime.Now.ToUniversalTime().Ticks - FROM_1970101);
            string timeStamp = toNow.Ticks.ToString();
            return long.Parse(timeStamp[0..^7]);
        }
        #endregion
        #region 类型
        /// <summary>
        /// 加解密类型
        /// </summary>
        public enum AuthcodeMode
        {
            [Description("加密")]
            Encode = 1,
            [Description("解密")]
            Decode = 2
        };
        /// <summary>
        /// 加解密错误类型
        /// </summary>
        [Flags]
        public enum AuthcodeError
        {

            [Description("正常")]
            Ok = 1,
            [Description("发生未知错误")]
            Error = 2,
            [Description("密钥或者源字符串为空")]
            Empty = 4,
            [Description("加密字符串已经过期")]
            Expriry = 8
        };
        /// <summary>
        /// 加解密返回结果
        /// </summary>
        public class AuthcodeResult
        {
            /// <summary>
            /// 错误代码
            /// </summary>
            [Description("错误代码")]
            public AuthcodeError Code;
            /// <summary>
            /// 返回值
            /// </summary>
            [Description("返回值")]
            public string Result;
        };
        #endregion
    }
}