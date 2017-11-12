using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars.CoAP.Codec;
using Com.AugustCellars.CoAP;

namespace Com.AugustCellars.CoAP.TLS
{
    class TLSMessageEncoder : CoAP.Spec.MessageEncoder18
    {
        const Int32 TokenLengthBits = 4;
        const Int32 CodeBits = 8;
        const Int32 OptionDeltaBits = 4;
        const Int32 OptionLengthBits = 4;
        const Byte PayloadMarker = 0xFF;

        protected override void Serialize(DatagramWriter writerFinal, Message msg, Int32 code)
        {
            DatagramWriter writer = new DatagramWriter();

            Int32 lastOptionNumber = 0;
            IEnumerable<Option> options = msg.GetOptions();

            foreach (Option opt in options) {
//                if (opt.Type == OptionType.Token)
//                    continue;

                // write 4-bit option delta
                Int32 optNum = (Int32) opt.Type;
                Int32 optionDelta = optNum - lastOptionNumber;
                Int32 optionDeltaNibble = GetOptionNibble(optionDelta);
                writer.Write(optionDeltaNibble, OptionDeltaBits);

                // write 4-bit option length
                Int32 optionLength = opt.Length;
                Int32 optionLengthNibble = GetOptionNibble(optionLength);
                writer.Write(optionLengthNibble, OptionLengthBits);

                // write extended option delta field (0 - 2 bytes)
                if (optionDeltaNibble == 13) {
                    writer.Write(optionDelta - 13, 8);
                }
                else if (optionDeltaNibble == 14) {
                    writer.Write(optionDelta - 269, 16);
                }

                // write extended option length field (0 - 2 bytes)
                if (optionLengthNibble == 13) {
                    writer.Write(optionLength - 13, 8);
                }
                else if (optionLengthNibble == 14) {
                    writer.Write(optionLength - 269, 16);
                }

                // write option value
                writer.WriteBytes(opt.RawValue);

                // update last option number
                lastOptionNumber = optNum;
            }

            Byte[] payload = msg.Payload;
            if (payload != null && payload.Length > 0) {
                // if payload is present and of non-zero length, it is prefixed by
                // an one-byte Payload Marker (0xFF) which indicates the end of
                // options and the start of the payload
                writer.WriteByte(PayloadMarker);
                writer.WriteBytes(payload);
            }

            // write fixed-size CoAP headers

            byte[] data = writer.ToByteArray();

            int lenNibble = GetOptionNibble(data.Length);
            writerFinal.Write(lenNibble, 4);
            writerFinal.Write(msg.Token == null ? 0 : msg.Token.Length, TokenLengthBits);
            if (lenNibble == 13) {
                writerFinal.Write(data.Length - 13, 8);
            }
            else if (lenNibble == 14) {
                writerFinal.Write(data.Length - 269, 16);
            }
            else if (lenNibble == 15)
            {
                writerFinal.Write(data.Length - 65805, 32);
            }

            writerFinal.Write(code, CodeBits);

            // write token, which may be 0 to 8 bytes, given by token length field
            writerFinal.WriteBytes(msg.Token);

            writerFinal.WriteBytes(data);

        }

        /// <summary>
        /// Returns the 4-bit option header value.
        /// </summary>
        /// <param name="optionValue">the option value (delta or length) to be encoded</param>
        /// <returns>the 4-bit option header value</returns>
        private static Int32 GetOptionNibble(Int32 optionValue)
        {
            if (optionValue <= 12)
                return optionValue;
            else if (optionValue <= 255 + 13)
                return 13;
            else if (optionValue <= 65535 + 269)
                return 14;
            else
                throw new Exception("optionValue" + ": Unsupported option delta " + optionValue);
        }
    }
}
