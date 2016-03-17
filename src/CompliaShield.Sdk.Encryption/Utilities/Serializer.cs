
namespace CompliaShield.Sdk.Cryptography.Utilities
{
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Configuration;
    using System.Data;
    using System.IO;
    using System.Linq;
    using System.Runtime.Serialization;
    using System.Runtime.Serialization.Formatters.Binary;
    using System.Xml;
    using System.Xml.Serialization;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Serialization;
    
    public class Serializer
    {   

        
        public static string SerializeToJson(object obj)
        {
            return SerializeToJson(obj, false);
        }

        public static string SerializeToJson(object obj, bool indented)
        {

            var settings = new JsonSerializerSettings()
            {
                ContractResolver = new CamelCasePropertyNamesContractResolver()
            };
            if (indented)
            {
                return JsonConvert.SerializeObject(obj, Newtonsoft.Json.Formatting.Indented, settings);
            }
            else
            {
                return JsonConvert.SerializeObject(obj, Newtonsoft.Json.Formatting.None, settings);
            }
        }

        public static string SerializeToJson(object obj, bool indented, ReferenceLoopHandling referenceLoopHandling)
        {
            var settings = new JsonSerializerSettings();
            settings.Formatting = indented ? Newtonsoft.Json.Formatting.Indented : Newtonsoft.Json.Formatting.None;
            settings.ReferenceLoopHandling = referenceLoopHandling;
            settings.ContractResolver = new CamelCasePropertyNamesContractResolver();
            return JsonConvert.SerializeObject(obj, settings);
        }

        public static string SerializeToJson(object obj, JsonSerializerSettings jsonSerializerSettings)
        {
            return JsonConvert.SerializeObject(obj, jsonSerializerSettings);
        }

        public static string SerializeJsonToXml(string json, string rootNode)
        {
            return SerializeJsonToXml(json, rootNode, false);
        }

        public static string SerializeJsonToXml(string json, string rootNode, bool indented)
        {
            var doc = JsonConvert.DeserializeXmlNode(json, rootNode);
            using (var stringWriter = new StringWriter())
            {
                var xmlSettings = new XmlWriterSettings() { Indent = indented };
                using (var xmlTextWriter = XmlWriter.Create(stringWriter, xmlSettings))
                {
                    doc.WriteTo(xmlTextWriter);
                    xmlTextWriter.Flush();
                    return stringWriter.GetStringBuilder().ToString();
                }
            }
        }

        public static object DeserializeFromJson(string jsonText, Type type)
        {
            return JsonConvert.DeserializeObject(jsonText, type);
        }
        
        public static T DeserializeFromJson<T>(string jsonText) where T : class
        {
            var type = typeof(T);
            return (T)DeserializeFromJson(jsonText, type);
            // return DeserializeFromJson<T>(jsonText, false);
        }
        
        /// <summary>
        /// Puts a serializable object to an XML string
        /// </summary>
        /// <param name="input"></param>
        /// <param name="type"></param>
        /// <returns></returns>
        /// <remarks></remarks>
        public static string SerializeToXml(object input)
        {
            return SerializeToXml(input, false, false, false);
        }

        public static string SerializeToXml(object input, bool indented)
        {
            return SerializeToXml(input, indented, false, false);
        }

        public static string SerializeToXml(object input, bool indented, bool verifyByDeserialize, bool autoStripBadCharactersIfFailsToDeserialize)
        {

            XmlSerializer s = new XmlSerializer(input.GetType());

            using (StringWriter sw = new StringWriter())
            {
                using (XmlTextWriter writer = new XmlTextWriter(sw))
                {


                    if (indented)
                    {
                        writer.Formatting = System.Xml.Formatting.Indented;
                    }
                    else
                    {
                        writer.Formatting = System.Xml.Formatting.None;
                    }

                    XmlSerializerNamespaces ns = new XmlSerializerNamespaces();
                    ns.Add("", "");
                    s.Serialize(writer, input, ns);
                    //s.Serialize(writer, input)

                    if (verifyByDeserialize)
                    {
                        string strReturn = sw.ToString();

                        //Added for additional checks when saving
                        try
                        {
                            DeserializeFromXml(strReturn, input.GetType());
                        }
                        catch (Exception ex)
                        {
                            //There is a problem
                            if (autoStripBadCharactersIfFailsToDeserialize)
                            {
                                strReturn = Format.StripInvalidXmlCharacters(strReturn);
                                try
                                {
                                    DeserializeFromXml(strReturn, input.GetType());
                                }
                                catch (Exception ex2)
                                {
                                    Exception ex3 = new Exception("StripInvalidXmlCharacters did not stop serialization error", ex2);
                                    throw ex3;
                                }
                            }
                            else
                            {
                                throw ex;
                            }
                        }

                        return strReturn;

                    }
                    else
                    {
                        return sw.ToString();
                    }
                }
            }
        }

        /// <summary>
        /// Puts a serializable object to an XML string
        /// </summary>
        /// <param name="input"></param>
        /// <param name="type"></param>
        /// <returns></returns>
        /// <remarks></remarks>
        public static string SerializeToXml(object input, System.Type type)
        {
            return SerializeToXml(input, type, false, false, false);
        }


        public static string SerializeToXml(object input, System.Type type, bool indented)
        {
            return SerializeToXml(input, type, indented, false, false);
        }

        public static string SerializeToXml(object input, System.Type type, bool indented, bool verifyByDeserialize, bool autoStripBadCharactersIfFailsToDeserialize)
        {

            XmlSerializer s = new XmlSerializer(type);

            StringWriter sw = new StringWriter();
            XmlTextWriter writer = new XmlTextWriter(sw);
            if (indented)
            {
                writer.Formatting = System.Xml.Formatting.Indented;
            }
            else
            {
                writer.Formatting = System.Xml.Formatting.None;
            }

            XmlSerializerNamespaces ns = new XmlSerializerNamespaces();
            ns.Add("", "");
            s.Serialize(writer, input, ns);
            if (verifyByDeserialize)
            {
                string strReturn = sw.ToString();

                //Added for additional checks when saving
                try
                {
                    DeserializeFromXml(strReturn, type);
                }
                catch (Exception ex)
                {
                    //There is a problem
                    if (autoStripBadCharactersIfFailsToDeserialize)
                    {
                        strReturn = Format.StripInvalidXmlCharacters(strReturn);
                        try
                        {
                            DeserializeFromXml(strReturn, type);
                        }
                        catch (Exception ex2)
                        {
                            Exception ex3 = new Exception("StripInvalidXmlCharacters did not stop serialization error", ex2);
                            throw ex3;
                        }
                    }
                    else
                    {
                        throw ex;
                    }
                }
                return strReturn;
            }
            else
            {
                return sw.ToString();
            }
        }

        /// <summary>
        /// Puts an XML string to an object
        /// </summary>
        /// <param name="xml"></param>
        /// <param name="type"></param>
        /// <returns></returns>
        /// <remarks></remarks>
        public static object DeserializeFromXml(string xml, System.Type type)
        {
            XmlSerializer s = new XmlSerializer(type);
            using (StringReader sr = new StringReader(xml))
            {
                using (XmlTextReader reader = new XmlTextReader(sr))
                {
                    return s.Deserialize(reader);
                }
            }
        }


        //---------------------

        // Convert an object to a byte array
        public static byte[] SerializeToByteArray(Object obj)
        {
            if (obj == null)
                return null;
            BinaryFormatter bf = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream())
            {
                bf.Serialize(ms, obj);
                return ms.ToArray();
            }
        }

        // Convert a byte array to an Object
        public static Object DeserializeFromByteArray(byte[] arrBytes)
        {
            using (var memStream = new MemoryStream())
            {
                BinaryFormatter binForm = new BinaryFormatter();
                memStream.Write(arrBytes, 0, arrBytes.Length);
                memStream.Seek(0, SeekOrigin.Begin);
                Object obj = (Object)binForm.Deserialize(memStream);
                return obj;
            }
        }

        public static Object DeserializeFromByteArray(byte[] arrBytes, SerializationBinder serializationBinder)
        {
            using (var memStream = new MemoryStream())
            {
                BinaryFormatter binForm = new BinaryFormatter();
                binForm.Binder = serializationBinder;
                memStream.Write(arrBytes, 0, arrBytes.Length);
                memStream.Seek(0, SeekOrigin.Begin);
                Object obj = (Object)binForm.Deserialize(memStream);
                return obj;
            }
        }

    }
}
