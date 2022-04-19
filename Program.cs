using System;
using System.Collections.Generic;
using System.IO;
using Tpm2Lib;

namespace TSStest
{
    /// <summary>
    /// Main class to contain the program of this sample.
    /// </summary>

    
    class Program
    {
        /// <summary>
        /// Defines the argument to use to have this program use a TCP connection
        /// to communicate with a TPM 2.0 simulator.
        /// </summary>
        private const string DeviceSimulator = "-tcp";
        /// <summary>
        /// Defines the argument to use to have this program use the Windows TBS
        /// API to communicate with a TPM 2.0 device.
        /// </summary>
        private const string DeviceWinTbs = "-tbs";
        /// <summary>
        /// The default connection to use for communication with the TPM.
        /// </summary>
        private const string DefaultDevice = DeviceSimulator;
        /// <summary>
        /// If using a TCP connection, the default DNS name/IP address for the
        /// simulator.
        /// </summary>
        private const string DefaultSimulatorName = "127.0.0.1";
        /// <summary>
        /// If using a TCP connection, the default TCP port of the simulator.
        /// </summary>
        private const int DefaultSimulatorPort = 2321;

        /// <summary>
        /// Prints instructions for usage of this program.
        /// </summary>
        static void WriteUsage()
        {
            Console.WriteLine();
            Console.WriteLine("Usage: GetCapabilities [<device>]");
            Console.WriteLine();
            Console.WriteLine("    <device> can be '{0}' or '{1}'. Defaults to '{2}'.", DeviceWinTbs, DeviceSimulator, DefaultDevice);
            Console.WriteLine("        If <device> is '{0}', the program will connect to a simulator\n" +
                              "        listening on a TCP port.", DeviceSimulator);
            Console.WriteLine("        If <device> is '{0}', the program will use the TBS interface to talk\n" +
                              "        to the TPM device.", DeviceWinTbs);
        }

        static Tpm2bPublicKeyRsa asd = new Tpm2bPublicKeyRsa();
        /// <summary>
        /// Parse the arguments of the program and return the selected values.
        /// </summary>
        /// <param name="args">The arguments of the program.</param>
        /// <param name="tpmDeviceName">The name of the selected TPM connection created.</param>
        /// <returns>True if the arguments could be parsed. False if an unknown argument or malformed
        /// argument was present.</returns>
        static bool ParseArguments(IEnumerable<string> args, out string tpmDeviceName)
        {
            tpmDeviceName = DefaultDevice;
            foreach (string arg in args)
            {
                if (string.Compare(arg, DeviceSimulator, true) == 0)
                {
                    tpmDeviceName = DeviceSimulator;
                }
                else if (string.Compare(arg, DeviceWinTbs, true) == 0)
                {
                    tpmDeviceName = DeviceWinTbs;
                }
                else
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Executes the GetCapabilities functionality. After parsing arguments, the 
        /// function connects to the selected TPM device and invokes the GetCapabilities
        /// command on that connection. If the command was successful, the retrieved
        /// capabilities are displayed.
        /// </summary>
        /// <param name="args">Arguments to this program.</param>

        public static TpmHandle CreateRsaPrimaryKey(Tpm2 tpm)
        {
            var sensCreate = new SensitiveCreate(new byte[] { 0xa, 0xb, 0xc }, null);
            TpmPublic parms = new TpmPublic(
                      TpmAlgId.Sha1,
                      ObjectAttr.Restricted | ObjectAttr.Decrypt | ObjectAttr.FixedParent | ObjectAttr.FixedTPM
                          | ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin,
                      null,
                      new RsaParms(
                          new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                          new NullAsymScheme(),
                          2048,
                          0),
                      new Tpm2bPublicKeyRsa());
            byte[] outsideInfo = new byte[] { 0, 1, 2 };
            var creationPcr = new PcrSelection(TpmAlgId.Sha1, new uint[] { 0, 1, 2 });
            TpmPublic pubCreated;
            CreationData creationData;
            TkCreation creationTicket;
            byte[] creationHash;
            TpmHandle h = tpm.CreatePrimary(TpmRh.Owner, sensCreate, parms, outsideInfo, new PcrSelection[] { creationPcr },
                          out pubCreated, out creationData, out creationHash, out creationTicket);
            return h;
        }

        public static TpmPrivate OnlyCreateSDKey(Tpm2 tpm, TpmHandle primHandle, out TpmPublic keyPublic)
        {
            TpmPublic keyInPublic = new TpmPublic(
                TpmAlgId.Sha1,
                ObjectAttr.Decrypt | ObjectAttr.Sign | ObjectAttr.FixedParent | ObjectAttr.FixedTPM
                    | ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin,
                null,
                new RsaParms(
                    new SymDefObject(),
                    new NullAsymScheme(),
                    2048, 0),
               new Tpm2bPublicKeyRsa());

            // This SensitiveCreate represents authetication key. It needs to be rememberd for later reconstruction.
            SensitiveCreate sensCreate = new SensitiveCreate(new byte[] { 2, 2, 3 }, null);
            CreationData keyCreationData;
            TkCreation creationTicket;
            byte[] creationHash;

            Console.WriteLine("Automatic authorization of a primary storage key.");

            TpmPrivate keyPrivate = tpm.Create(primHandle,
                                               sensCreate,
                                               keyInPublic,
                                               null,
                                               new PcrSelection[0],
                                               out keyPublic,
                                               out keyCreationData,
                                               out creationHash,
                                               out creationTicket);

            return keyPrivate;
        }

        public static TpmHandle OnlyLoadSDKey(Tpm2 tpm, TpmHandle primHandle,
                                              TpmPrivate keyPrivate, TpmPublic keyPublic)
        {
            TpmHandle keyHandle = null;

            Console.WriteLine("Strict mode.");

            //
            // Switch TPM object to the strict mode. (Note that this is a TSS.Net
            // specific piece of functionality, not a part of TPM 2.0 specification).
            //
            tpm._Behavior.Strict = true;

            //
            // No auth session is added automatically when TPM object is in strict mode.
            //
            tpm._ExpectError(TpmRc.AuthMissing)
               .Load(primHandle, keyPrivate, keyPublic);

            //
            // Now explicitly request an auth session of a desired type.
            // The actual auth value will be supplied by TSS.Net implicitly.
            //
            keyHandle = tpm[Auth.Default].Load(primHandle, keyPrivate, keyPublic);

            Console.WriteLine("Signing decryption key created.");

            //
            // Switch TPM object back to the normal mode.
            //
            tpm._Behavior.Strict = false;

            return keyHandle;
        }

        public static void WriteToBinaryFile<T>(string filePath, T objectToWrite, bool append = false)
        {
            using (Stream stream = File.Open(filePath, append ? FileMode.Append : FileMode.Create))
            {
                var binaryFormatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                binaryFormatter.Serialize(stream, objectToWrite);
            }
        }

        public static T ReadFromBinaryFile<T>(string filePath)
        {
            using (Stream stream = File.Open(filePath, FileMode.Open))
            {
                var binaryFormatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                return (T)binaryFormatter.Deserialize(stream);
            }
        }




        public static TpmRc LastError = TpmRc.Success;

        public static TpmHandle PersRsaPrimOwner = null;
        public static TpmHandle PersRsaPrimPlatform = null;
        public static TpmHandle PersRsaPrimEndors = null;

        public static uint NextPersHandle = (uint)TpmHc.PersistentFirst;
        public static uint NextPlatformPersHandle = (uint)TpmHc.PlatformPersistent;

        public static TpmHandle GeneratePersistentHandle(ref uint nextHandle,
                                                   TpmHc first, TpmHc last,
                                                   TpmHandle pers1,
                                                   TpmHandle pers2 = null)
        {
            if (nextHandle == (uint)last)
                nextHandle = (uint)first;

            while (pers1 != null && nextHandle == pers1.handle ||
                   pers2 != null && nextHandle == pers2.handle)
            {
                ++nextHandle;
            }
            return new TpmHandle(nextHandle++);
        }

        public static TpmHandle NextPersistentHandle(TpmRh hierarchy = TpmRh.Owner)
        {
            if (hierarchy == TpmRh.Owner || hierarchy == TpmRh.Endorsement)
                {
                    return GeneratePersistentHandle(ref NextPersHandle,
                    TpmHc.PersistentFirst, TpmHc.PlatformPersistent - 1,
                    PersRsaPrimOwner, PersRsaPrimEndors);
            }
            else if (hierarchy == TpmRh.Platform)
            {
                return GeneratePersistentHandle(ref NextPlatformPersHandle,
                        TpmHc.PlatformPersistent, TpmHc.PersistentLast,
                        PersRsaPrimPlatform);
            }
            return null;
        }

        public bool _LastCommandSucceeded()
        {
            return LastError == TpmRc.Success;
        }

        static void Main(string[] args)
        {
            //
            // Parse the program arguments. If the wrong arguments are given or
            // are malformed, then instructions for usage are displayed and 
            // the program terminates.
            // 
            string tpmDeviceName;
            if (!ParseArguments(args, out tpmDeviceName))
            {
                WriteUsage();
                return;
            }

            
            //
            // Create the device according to the selected connection.
            // 
            Tpm2Device tpmDevice;
            switch (tpmDeviceName)
            {
                case DeviceSimulator:
                    tpmDevice = new TcpTpmDevice(DefaultSimulatorName, DefaultSimulatorPort);
                    break;

                case DeviceWinTbs:
                    tpmDevice = new TbsDevice();
                    break;

                default:
                    throw new Exception("Unknown device selected.");
            }

            //
            // Connect to the TPM device. This function actually establishes the
            // connection.
            // 
            tpmDevice.Connect();

            //
            // Pass the device object used for communication to the TPM 2.0 object
            // which provides the command interface.
            // 
            var tpm = new Tpm2(tpmDevice);

            if (tpmDevice is TcpTpmDevice)
            {
                //
                // If we are using the simulator, we have to do a few things the
                // firmware would usually do. These actions have to occur after
                // the connection has been established.
                //
                tpmDevice.PowerCycle();
                tpm.Startup(Su.Clear);
            }

            // Supply with paths
            string pathHandle = @"C:\Users\Kostas\Desktop\handle";
            string pathCipher = @"C:\Users\Kostas\Desktop\ctext";

            var scheme = new SchemeOaep(TpmAlgId.Sha1);
            var message = new byte[] { 1, 2, 3 };

            byte[] cipherText = new byte[] { };
            byte[] decryptedText;

            TpmHandle handle = new TpmHandle();
            TpmHandle primKeyHandle = new TpmHandle();
            TpmPrivate privKey;
            TpmPublic keyPublic;
            
            TpmHandle hPers = new TpmHandle();
            TpmHandle hPers2 = new TpmHandle();

            Console.WriteLine(
                    "0 - Create Primary Key\n" +
                    "1 - Create child key on PrimKey and load it\n" +
                    "2 - Try one session RsaEncrypt and RsaDecrypt\n" +
                    "3 - Create persisten handle from child key\n" +
                    "4 - Export persisten handle to file\n" +
                    "5 - RsaEncrypt with persisten handle and export it to file\n" +
                    "6 - Load cipher text and persisten key from file and construct the key\n" +
                    "7 - Decrypt loaded cipher text with constructed persistent key\n" +
                    "8 - Exit");

            while (true)
            {
                Console.WriteLine("Choose:");
                var input = Console.ReadLine();
                
                if (input == "0")
                {
                    Console.WriteLine("CreateRsaPrimaryKey ...");
                    primKeyHandle = CreateRsaPrimaryKey(tpm);
                }

                if (input == "1")
                {
                    Console.WriteLine("OnlyCreateSDKey and OnlyLoadSDKey...");

                    privKey = OnlyCreateSDKey(tpm, primKeyHandle, out keyPublic);
                    handle = OnlyLoadSDKey(tpm, primKeyHandle, privKey, keyPublic);
                }

                if (input == "2")
                {
                    Console.WriteLine("RsaEncrypt and RsaDecrypt...");

                    cipherText = tpm.RsaEncrypt(handle, message, scheme, null);
                    decryptedText = tpm.RsaDecrypt(handle, cipherText, scheme, null);
                }

                if (input == "3")
                {
                    Console.WriteLine("Creating persisten handle...");
                    hPers = NextPersistentHandle(TpmRh.Owner);
                    tpm._ExpectResponses(TpmRc.Success, TpmRc.NvSpace, TpmRc.NvDefined)
                        .EvictControl(TpmRh.Owner, handle, hPers);

                    tpm.FlushContext(handle);
                    if (tpm._LastCommandSucceeded())
                    {
                        Console.WriteLine("Success, handle: " + hPers.handle.ToString());
                    }
                }

                if (input == "4")
                {
                    Console.WriteLine("Writing to file...");
                    WriteToBinaryFile(pathHandle, hPers.handle);
                }

                if (input == "5")
                {
                    Console.WriteLine("Encrypting with persistent handle...");
                    cipherText = tpm.RsaEncrypt(hPers, message, scheme, null);
                    WriteToBinaryFile(pathCipher, cipherText);
                }

                if (input == "6")
                {
                    Console.WriteLine("Reading cipher text from file...");
                    cipherText = ReadFromBinaryFile<byte[]>(pathCipher);

                    Console.WriteLine("Reading handle from file...");
                    uint tmpHandle = ReadFromBinaryFile<uint>(pathHandle);

                    Console.WriteLine("Constructing handle...");
                    hPers2 = new TpmHandle(tmpHandle);
                    hPers2.Auth = new byte[] { 2, 2, 3 };
                }

                if (input == "7")
                {
                    Console.WriteLine("RsaDecrypt with recreated persisten handle...");
                    decryptedText = tpm.RsaDecrypt(hPers2, cipherText, scheme, null);
                    Console.WriteLine(BitConverter.ToString(decryptedText));
                }

                if (input == "8")
                {
                    break;
                }

            }
            //
            // Clean up.
            // 
            tpm.Dispose();
            

            Console.WriteLine("Press Any Key to continue.");
            Console.ReadKey();
        }
    }
}