using System;
using System.ComponentModel;
using System.Reflection;

namespace Sudo.Common
{
    /// <summary>
    /// Enum扩展方法
    /// </summary>
    public static class EnumEx
    {
        /// <summary>
        /// 获取枚举类型描述信息
        /// </summary>
        /// <param name="val">枚举类型值</param>
        /// <returns>描述信息</returns>
        public static string GetDescription(this Enum val)
        {
            Type type = val.GetType();
            MemberInfo[] minfo = type.GetMember(val.ToString());
            if (minfo != null && minfo.Length > 0)
            {
                object[] attrs = minfo[0].GetCustomAttributes(typeof(DescriptionAttribute), false);
                if (attrs != null && attrs.Length > 0)
                {
                    return ((DescriptionAttribute)attrs[0]).Description;
                }
            }
            return val.ToString();
        }
        /// <summary>判断枚举类型是否设置flag标志</summary>
		/// <returns>True/False</returns>
		public static bool IsFlagSet()
        {
            return Attribute.IsDefined(typeof(Enum), typeof(FlagsAttribute));
        }
    }
}