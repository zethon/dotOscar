using System;
using System.Net;
using System.Text;
using System.Collections;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;


namespace DotOSCAR
{
	struct flap_header 
	{
		public char asterisk;
		public byte frametype;
		public short seqno;
		public short datalen;
	};

	class TLV
	{
		public short type;
		public short length;
		public byte[] byteData = new byte[1024*4];
	};

	class SNAC
	{
		public short family;
		public short subtype;
		public short flags;
		public int requestid;
	}

	/// <summary>
	/// Summary description for Class1.
	/// </summary>
	public class OSCAR
	{
		const byte FLAP_HEADER_LENGTH = 6;
		const byte SNAC_HEADER_LENGTH = 10;

		// properties
		private bool m_bAutoReconnect = false;
		public bool AutoReconnect
		{
			get { return m_bAutoReconnect; }
			set { m_bAutoReconnect = value; }
		}

		public bool Connected
		{
			get { return m_socket.Connected; }
		}

		// delegates & callbacks
		public delegate void OnReconnectHandler();
		public event OnReconnectHandler OnReconnect;

		public delegate void OnDisconnectHandler();
		public event OnDisconnectHandler OnDisconnect;

		public delegate void OnErrorHandler(string strError);
		public event OnErrorHandler OnError;

		public delegate void OnSNACHandler(string strSNACID);
		public event OnSNACHandler OnSNAC;

		public delegate void OnIMInHandler(string strUser, string strMsg, bool bAuto);
		public event OnIMInHandler OnIMIn;

		public delegate void OnUpdateBubbyHandler(string strUser, bool bOnline);
		public event OnUpdateBubbyHandler OnUpdateBuddy;

		public delegate void OnSignedOnHandler();
		public event OnSignedOnHandler OnSignedOn;

		// private variables
		private bool m_bDCOnPurpose = false;
		private string m_uin = "";		
		private string m_pw = "";

		private Socket m_socket;
		private Byte[] m_byBuff = new Byte[32767];
		private int m_iSeqNum = 0x4772;
		
		// login information
		private bool m_bAuthenticated = false;
		private bool m_bTCPConnected = false;
		private byte [] m_authCookie;
		private string m_strBOSServer;
		private string m_strBOSPort;

		public OSCAR()
		{
		}

		public OSCAR(string strUIN, string strPW)
		{
			m_uin = strUIN;		
			m_pw = strPW;
		}

		public bool Connect(string strUIN, string strPW)
		{
			m_uin = strUIN;		
			m_pw = strPW;
			return Connect();
		}

		public bool Connect()
		{
			IPAddress ip;
			int port;

			if (!m_bAuthenticated)
			{
				ip = Dns.Resolve("login.oscar.aol.com").AddressList[0];
				port = 5190;
			}
			else
			{
				ip = Dns.Resolve(m_strBOSServer).AddressList[0];
				port = int.Parse(m_strBOSPort);
			}
			
			IPEndPoint remote = new IPEndPoint(ip,port);

			try 
			{
				m_socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
				m_socket.Blocking = false ;	
				m_socket.BeginConnect(remote , new AsyncCallback(OnConnect), m_socket);
			}
			catch (Exception er)
			{
				DispatchError(er.Message);
				return false;
			}

			return true;
		}

		public void OnConnect(IAsyncResult ar)
		{
			Socket sock = (Socket)ar.AsyncState;

			// Check if we were sucessfull
			try
			{
				if (sock.Connected)
				{
					m_bTCPConnected = true;

					if (!m_bAuthenticated)
						SendClientIdent();
					else
						SendLoginCookie();

					SetupRecieveCallback(sock);

				}
				else
					DispatchError("Connection failed.");
			}
			catch( Exception ex )
			{
				DispatchError(ex.Message);
			}  
		}

		private void SetupRecieveCallback(Socket sock)
		{
			if (sock == null || !m_bTCPConnected)
				return;

			try
			{
				AsyncCallback recieveData = new AsyncCallback(OnRecievedData);
				sock.BeginReceive(m_byBuff, 0, m_byBuff.Length, SocketFlags.None,recieveData, sock);
			}
			catch( Exception ex )
			{
				DispatchError(ex.Message);
			}
		}

		public void OnRecievedData( IAsyncResult ar )
		{
			Socket sock = (Socket)ar.AsyncState;

			try
			{
				int nBytesRead = 0;
				int nBytesRec = sock.EndReceive( ar );
				if( nBytesRec > 0 )
				{
					do 
					{
						// build the flap header
						flap_header fh = new flap_header();
						fh.asterisk = (char)m_byBuff[nBytesRead+0];
						fh.frametype = (byte)m_byBuff[nBytesRead+1];

						byte [] byteTemp = new byte[2];
						byteTemp[1] = m_byBuff[nBytesRead+2];
						byteTemp[0] = m_byBuff[nBytesRead+3];
						fh.seqno = BitConverter.ToInt16(byteTemp,0);

						byteTemp[1] = m_byBuff[nBytesRead+4];
						byteTemp[0] = m_byBuff[nBytesRead+5];
						fh.datalen = BitConverter.ToInt16(byteTemp,0);

						#region do-while-loop
						// we're talking to the authentication server
						if (!m_bAuthenticated)
						{
							if (fh.frametype == 4)
							{
								byteTemp = new byte[fh.datalen];
								Array.Copy(m_byBuff,nBytesRead+6,byteTemp,0,fh.datalen);
								Hashtable loginInfo = GetTLVHash(byteTemp,fh.datalen);
							
								// authentication error
								if (loginInfo["8"] != null)
								{
									TLV tlv = (TLV)loginInfo[8];
									if (OnError != null)
										OnError("Error Code ("+Encoding.ASCII.GetString(tlv.byteData,0,2)+")");									
									m_socket.Shutdown(SocketShutdown.Both);
									m_socket.Close();
									m_bTCPConnected = false;
								}
									// success!
								else if (loginInfo["6"] != null)
								{
									// set the BOS info
									TLV tlv = (TLV)loginInfo["5"];
									string strTemp = Encoding.ASCII.GetString(tlv.byteData,0,tlv.length);
									string [] strData = Regex.Split(strTemp,"(:)");
									m_strBOSServer = strData[0];
									m_strBOSPort = strData[2];

									// set the auth cookie
									TLV cookie = (TLV)loginInfo["6"];
									m_authCookie = new byte[cookie.length];
									Array.Copy(cookie.byteData,0,m_authCookie,0,cookie.length);
								
									// shut down and connect to BOS
									m_bAuthenticated = true;
									m_bTCPConnected = false;
									m_socket.Shutdown(SocketShutdown.Both);
									m_socket.Close();
									Connect();
								}
							}
						}
						else
						{
							// SNAC data is always on flap channel 2
							if (fh.frametype == 2)
							{
								byte [] rawData = new byte[fh.datalen];
								Array.Copy(m_byBuff,nBytesRead+6,rawData,0,fh.datalen);

								// build the snac
								SNAC snac = new SNAC();
								snac.family = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(rawData,0));
								snac.subtype = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(rawData,2));
								snac.flags = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(rawData,4));
								snac.requestid =  IPAddress.NetworkToHostOrder(BitConverter.ToInt32(rawData,6));
							
								// get the snac data
								byte [] snacData = new byte[fh.datalen-10];
								Array.Copy(rawData,10,snacData,0,fh.datalen-10);

								// send it on its way
								DispatchSNACData(snac,snacData);
							}
						}
						#endregion

						nBytesRead += fh.datalen + FLAP_HEADER_LENGTH;
					
					} while (nBytesRead < nBytesRec);

					SetupRecieveCallback (sock);
				}
				else if (!m_bDCOnPurpose)
					HandleReconnect(); // looks like we disconnect, so reconnect
			}
			catch( Exception ex )
			{
				// looks like the connection dropped
				if (!m_bDCOnPurpose)
					HandleReconnect();
			}
		}

		private void HandleReconnect()
		{
//			m_socket.Shutdown(SocketShutdown.Both);
//			m_socket.Close();
//			if (OnDisconnect != null)
//				OnDisconnect();	
			
			Disconnect();

			if (AutoReconnect)
			{
				if (OnReconnect != null)
					OnReconnect();
						
				Thread.Sleep(500);

				Connect();
			}
		}

		private void DispatchSNACData(SNAC snac, byte [] byteData)
		{
			string strSnacID = string.Format("{0:X2}:{1:X2}",snac.family,snac.subtype);
			
			if (OnSNAC != null)
				OnSNAC(strSnacID);

			switch (strSnacID)
			{
					// error!
				case "02:01":
					break;

					// message in
				case "04:07":
					MessageIn(byteData);
					break;

					// buddy signed on
				case "03:0B":
					UserSignedOn(byteData);
					break;

					// signed off
				case "03:0C":
					UserSignedOff(byteData);
					break;

					#region login cases
					// login procedure
				case "01:03":
					byte [] outData = {0,1,0,3,0,2,0,1,0,3,0,1,0,21,0,1,0,4,0,1,0,6,0,1,0,9,0,1,0,10,0,1};
					SendSnacPacket(GetSNACHeader(0x1,0x17,0x0,0x17),outData);
					break;

					// login procedure
				case "01:18":
					//SNAC(04,02)
					byte [] outData3 = {0,0,0,0,0,3,0x1f,0x40,3,0xe7,3,0xef,0,0,0,0};
					SendSnacPacket(GetSNACHeader(0x04,0x02,0x00,0x02),outData3);

					// SNAC (02,04)
					byte [] outData2 = {0x00,0x05,0x00,0x30,0x09,0x46,0x13,0x49,0x4C,0x7F,0x11,
										   0xD1,0x82,0x22,0x44,0x45,0x53,0x54,0x00,0x00,0x09,0x46,
										   0x13,0x44,0x4C,0x7F,0x11,0xD1,0x82,0x22,0x44,0x45,0x53,
										   0x54,0x00,0x00,0x09,0x46,0x13,0x4E,0x4C,0x7F,0x11,0xD1,
										   0x82,0x22,0x44,0x45,0x53,0x54,0x00,0x00};
					SendSnacPacket(GetSNACHeader(0x02,0x04,0x00,0x04),outData2);

					// SNAC (03,04)
					byte [] newData1 = {0x09,0x31,0x36,0x31,0x39,0x36,0x32,0x33,0x39,0x34};
					SendSnacPacket(GetSNACHeader(0x03,0x04,0x00,0x04),newData1);

					// SNAC (01,1E)
					byte [] outData4 = {0x00,0x06,0x00,0x04,0xFF,0xFF,0x00,0x00,0x00,0x08,0x00,0x02,
										   0x00,0x00,0x00,0x0C,0x00,0x25,0xC0,0xA8,0x01,0x64,0x00,0x00,
										   0x0C,0xE0,0x04,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
										   0x50,0x00,0x00,0x00,0x03,0xFF,0xFF,0xFF,0xAB,0x00,0x00,0x00,
										   0x00,0xBE,0xBA,0xAD,0xDE,0x00,0x00};
					SendSnacPacket(GetSNACHeader(0x01,0x1e,0x00,0x1e),outData4);

					// SNAC (01,02) Client Ready
					byte [] newData3 = {0x00,0x01,0x00,0x03,0x01,0x10,0x02,0x8A,0x00,0x02,0x00,
										   0x01,0x01,0x01,0x02,0x8A,0x00,0x03,0x00,0x01,0x01,0x10,
										   0x02,0x8A,0x00,0x15,0x00,0x01,0x01,0x10,0x02,0x8A,0x00,
										   0x04,0x00,0x01,0x01,0x10,0x02,0x8A,0x00,0x06,0x00,0x01,
										   0x01,0x10,0x02,0x8A,0x00,0x09,0x00,0x01,0x01,0x10,0x02,
										   0x8A,0x00,0x0A,0x00,0x01,0x01,0x10,0x02,0x8A};
					SendSnacPacket(GetSNACHeader(0x01,0x2,0x00,0x2),newData3);

					if (OnSignedOn != null)
						OnSignedOn();
					break;
					#endregion

				default:
					break;
			}
		}

		public void MessageIn(byte [] Data)
		{
			short iNameLen = Data[10];
			string strSender = Encoding.ASCII.GetString(Data,11,iNameLen);
			string strMessage;
			bool bAway = false;

			int iTlvNumIdx = 11+iNameLen+2;
			int iNumTLVs = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(Data,iTlvNumIdx));

			// read through the TLVs
			int iTlvStart = iTlvNumIdx + 2;
			while (iTlvStart < Data.Length)
			{
				TLV tlv = new TLV();
				tlv.type = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(Data,iTlvStart));
				tlv.length = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(Data,iTlvStart+2));
				
				if (tlv.type == 0x01)
				{
					// user status
					int iOffset = iTlvStart + 4;
					short iStatus = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(Data,iOffset));
					bAway = (0x20 & iStatus) != 0;
				}
				if (tlv.type == 0x02)
				{
					int iOffset = iTlvStart + 4;
					while (iOffset < (iTlvStart + 4 + tlv.length))
					{
						TLV subtlv = new TLV();
						subtlv.type = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(Data,iOffset));
						subtlv.length = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(Data,iOffset+2));

						if (subtlv.type == 0x101)
						{
							int iMsgOffset = iOffset+8;
							strMessage = Encoding.ASCII.GetString(Data,iMsgOffset,subtlv.length-4);

							OnIMIn(Normalize(strSender),Regex.Replace(strMessage,@"<(.|\n)*?>",string.Empty),bAway);
							return;
						}
						iOffset += 4+subtlv.length;
					}
				}
				
				iTlvStart += 4+tlv.length;
			}
		}

		public static string Normalize(string strScreenName)
		{
			string strName= strScreenName;
			strName = Regex.Replace(strName," ","");
			strName = strName.ToLower();
			return strName;
		}

	
		public void SendMessage(string strUIN, string strMessage)
		{
			int iSize = 0;

			byte [] msgCookie = {0x52,0x99,0x5d,0x0,0x69,0x23,0x0,0x0};
			iSize += msgCookie.Length;

			byte [] msgChannel = {0x0,01};
			iSize += msgChannel.Length;

			byte [] UINInfo = new byte[strUIN.Length+1];
			UINInfo[0] = (byte)strUIN.Length;
			iSize++;
			Array.Copy(Encoding.Default.GetBytes(strUIN),0,UINInfo,1,strUIN.Length);
			iSize += strUIN.Length;

			// TLV 0501 (embedded in tlv 02)
			byte [] tlv0501 = new byte[5];
			tlv0501 = GetTLVBytes(0x0501,new byte [] {1});

			// TLV 0101 (embedded in tlv 02)
			byte [] txtData = new byte[strMessage.Length+4];
			txtData[0] = 0x0; txtData[1] = 0x0;
			txtData[2] = 0xFF; txtData[3] = 0xFF;
			Array.Copy(Encoding.Default.GetBytes(strMessage),0,txtData,4,strMessage.Length);

			byte [] temp = new byte[txtData.Length+tlv0501.Length+4];
			Array.Copy(tlv0501,0,temp,0,tlv0501.Length);
			Array.Copy(GetTLVBytes(0x0101,txtData),0,temp,tlv0501.Length,txtData.Length+4);

			byte [] tlv02 = GetTLVBytes(0x02,temp);
			iSize += tlv02.Length;

			byte [] tlv06 = {0x00,0x06,0x00,0x00};
			iSize += tlv06.Length;

			// build the outgoin packet
			int iOffset = 0;
			byte [] Data = new byte[iSize];
			Array.Copy(msgCookie,0,Data,iOffset,msgCookie.Length);
			iOffset += msgCookie.Length;
			Array.Copy(msgChannel,0,Data,iOffset,msgChannel.Length);
			iOffset += msgChannel.Length;
			Array.Copy(UINInfo,0,Data,iOffset,UINInfo.Length);
			iOffset += UINInfo.Length;
			Array.Copy(tlv02,0,Data,iOffset,tlv02.Length);
			iOffset += tlv02.Length;
			Array.Copy(tlv06,0,Data,iOffset,tlv06.Length);
			iOffset += tlv06.Length;

			SendSnacPacket(GetSNACHeader(0x04,0x06,0x00,0x00),Data);
		}
		
		private void UserSignedOn(byte [] Data)
		{
			short iNameLen = Data[0];
			string strName = Encoding.ASCII.GetString(Data,1,iNameLen);

			if (OnUpdateBuddy != null)
				OnUpdateBuddy(Normalize(strName),true);
		}
		
		private void UserSignedOff(byte [] Data)
		{
			short iNameLen = Data[0];
			string strName = Encoding.ASCII.GetString(Data,1,iNameLen);

			if (OnUpdateBuddy != null)
				OnUpdateBuddy(Normalize(strName),false);
		}

		public void SendSnacPacket(byte [] snacHeader, byte [] snacData)
		{
			int iDataLen = snacData != null ? snacData.Length : 0;
			int iBufferLen = FLAP_HEADER_LENGTH + SNAC_HEADER_LENGTH + iDataLen;
			byte [] outBuffer = new byte[iBufferLen];

			Array.Copy(GetFlapHeader(SNAC_HEADER_LENGTH+iDataLen),0,outBuffer,0,FLAP_HEADER_LENGTH);
			Array.Copy(snacHeader,0,outBuffer,FLAP_HEADER_LENGTH,SNAC_HEADER_LENGTH);
			
			if (iDataLen > 0)
				Array.Copy(snacData,0,outBuffer,FLAP_HEADER_LENGTH+SNAC_HEADER_LENGTH,iDataLen);
			
			m_socket.Send(outBuffer,iBufferLen,0);
		}
		
		public void SendSnacPacket(byte [] snacHeader)
		{
			SendSnacPacket(snacHeader,null);
		}

		public byte[] GetSNACHeader(int sFamily, int sSubtype, int sFlags, long iReqID)
		{
			byte [] retVal = new byte[SNAC_HEADER_LENGTH];

			retVal[0] = (byte)BitConverter.ToChar(BitConverter.GetBytes(sFamily),1);
			retVal[1] = (byte)BitConverter.ToChar(BitConverter.GetBytes(sFamily),0);

			retVal[2] = (byte)BitConverter.ToChar(BitConverter.GetBytes(sSubtype),1);
			retVal[3] = (byte)BitConverter.ToChar(BitConverter.GetBytes(sSubtype),0);

			retVal[4] = (byte)BitConverter.ToChar(BitConverter.GetBytes(sFlags),1);
			retVal[5] = (byte)BitConverter.ToChar(BitConverter.GetBytes(sFlags),0);

			retVal[6] = (byte)BitConverter.ToChar(BitConverter.GetBytes(iReqID),3);
			retVal[7] = (byte)BitConverter.ToChar(BitConverter.GetBytes(iReqID),2);
			retVal[8] = (byte)BitConverter.ToChar(BitConverter.GetBytes(iReqID),1);
			retVal[9] = (byte)BitConverter.ToChar(BitConverter.GetBytes(iReqID),0);

			return retVal;
		}

		private byte[] GetFlapHeader(int iMsgLen)
		{
			return GetFlapHeader(iMsgLen,2);
		}

		private byte[] GetFlapHeader(int iMsgLen, int iFlapType)
		{
			byte [] retVal = new byte[6];
			retVal[0] = (byte)Encoding.ASCII.GetBytes("*")[0];
			retVal[1] = (byte)iFlapType;

			m_iSeqNum++;

			retVal[2] = (byte)BitConverter.ToChar(BitConverter.GetBytes(m_iSeqNum),1);
			retVal[3] = (byte)BitConverter.ToChar(BitConverter.GetBytes(m_iSeqNum),0);

			retVal[4] = (byte)BitConverter.ToChar(BitConverter.GetBytes(iMsgLen),1);
			retVal[5] = (byte)BitConverter.ToChar(BitConverter.GetBytes(iMsgLen),0);

			return retVal;
		}

		public void SendLoginCookie()
		{
			byte [] packet1 = new byte[1024*4];
			byte [] packet = new byte[1024*4];
			int iIndex = 4;
			packet[0] = 0;
			packet[1] = 0;
			packet[2] = 0;
			packet[3] = 1;

			Array.Copy(GetTLVBytes(0x06,m_authCookie),0,packet,iIndex,m_authCookie.Length+4);
			iIndex += m_authCookie.Length+4;

			Array.Copy(GetFlapHeader(iIndex,1),0,packet1,0,6);
			Array.Copy(packet,0,packet1,6,iIndex);	
			m_socket.Send(packet1,iIndex+6,0);
		}


		#region GetTLVByte Procedures
		private byte[] GetTLVBytes(int iType, string strData)
		{
			byte [] retVal = new byte[2+2+strData.Length];

			retVal[0] = (byte)BitConverter.ToChar(BitConverter.GetBytes(iType),1);
			retVal[1] = (byte)BitConverter.ToChar(BitConverter.GetBytes(iType),0);

			retVal[2] = (byte)BitConverter.ToChar(BitConverter.GetBytes(strData.Length),1);
			retVal[3] = (byte)BitConverter.ToChar(BitConverter.GetBytes(strData.Length),0);

			Array.Copy(Encoding.Default.GetBytes(strData),0,retVal,4,strData.Length);
			
			return retVal;
		}

		private byte[] GetTLVBytes(int iType, byte [] byteData)
		{
			byte [] retVal = new byte[2+2+byteData.Length];

			retVal[0] = (byte)BitConverter.ToChar(BitConverter.GetBytes(iType),1);
			retVal[1] = (byte)BitConverter.ToChar(BitConverter.GetBytes(iType),0);

			retVal[2] = (byte)BitConverter.ToChar(BitConverter.GetBytes(byteData.Length),1);
			retVal[3] = (byte)BitConverter.ToChar(BitConverter.GetBytes(byteData.Length),0);

			Array.Copy(byteData,0,retVal,4,byteData.Length);
			
			return retVal;
		}

		private byte[] GetTLVBytes(int iType, int iData)
		{
			byte [] retVal = new byte[2+2+2];

			retVal[0] = (byte)BitConverter.ToChar(BitConverter.GetBytes(iType),1);
			retVal[1] = (byte)BitConverter.ToChar(BitConverter.GetBytes(iType),0);

			retVal[2] = 0;
			retVal[3] = 2;

			retVal[4] = (byte)BitConverter.ToChar(BitConverter.GetBytes(iData),1);
			retVal[5] = (byte)BitConverter.ToChar(BitConverter.GetBytes(iData),0);

			return retVal;
		}
		#endregion

		public void SendClientIdent()
		{
			byte [] packet1 = new byte[1024*4];
			byte [] packet = new byte[1024*4];
			int iIndex = 4;
			string strTemp = "";
			
			packet[0] = 0;
			packet[1] = 0;
			packet[2] = 0;
			packet[3] = 1;

			// TLV 01
			Array.Copy(GetTLVBytes(1,m_uin),0,packet,iIndex,m_uin.Length+4);
			iIndex += m_uin.Length+4;

			// TLV 02
			Array.Copy(GetTLVBytes(2,RoastedPassword(m_pw)),0,packet,iIndex,RoastedPassword(m_pw).Length+4);
			iIndex += RoastedPassword(m_pw).Length+4;

			// TLV 03   
			strTemp = @"ICQ Inc. - Product of ICQ (TM).2000b.4.63.1.3279.85";
			Array.Copy(GetTLVBytes(3,strTemp),0,packet,iIndex,strTemp.Length+4);
			iIndex += strTemp.Length+4;

			// TLV 22 (CLIENTID)
			Array.Copy(GetTLVBytes(22,266),0,packet,iIndex,6);
			iIndex += 6;

			// TLV 23 (VER_MAJOR)
			Array.Copy(GetTLVBytes(23,5),0,packet,iIndex,6);
			iIndex += 6;

			// TLV 24 (VER_MINOR)
			Array.Copy(GetTLVBytes(24,63),0,packet,iIndex,6);
			iIndex += 6;
			
			// TLV 25 (VER_LESSER)
			Array.Copy(GetTLVBytes(25,1),0,packet,iIndex,6);
			iIndex += 6;

			// TLV 26 (VER_BUILD)
			Array.Copy(GetTLVBytes(26,3279),0,packet,iIndex,6);
			iIndex += 6;

			// TLV 20 (VER_DISTRIB)
			packet[iIndex++] = 0x00;
			packet[iIndex++] = 0x14;
			packet[iIndex++] = 0x00;
			packet[iIndex++] = 0x04;
			packet[iIndex++] = 0x00;
			packet[iIndex++] = 0x00;
			packet[iIndex++] = 0x00;
			packet[iIndex++] = 85;

			// TLV 15 (LANGUAGE)
			strTemp = "en";
			Array.Copy(GetTLVBytes(15,strTemp),0,packet,iIndex,strTemp.Length+4);
			iIndex += strTemp.Length+4;

			// TLV 14 (COUNTRY)
			strTemp = "us";
			Array.Copy(GetTLVBytes(14,strTemp),0,packet,iIndex,strTemp.Length+4);
			iIndex += strTemp.Length+4;

			Array.Copy(GetFlapHeader(iIndex,1),0,packet1,0,6);
			Array.Copy(packet,0,packet1,6,iIndex);
			m_socket.Send(packet1,iIndex+6,0);
		}

		public byte[] RoastedPassword(string strOrig)
		{
			byte [] retVal = new byte[strOrig.Length];
			byte [] roaster = {0xF3, 0x26, 0x81, 0xC4, 0x39, 0x86, 0xDB, 0x92, 0x71, 
								  0xA3, 0xB9, 0xE6, 0x53, 0x7A, 0x95, 0x7C};
			
			for (int i=0 ; i < strOrig.Length; i++) 
			{
				retVal[i] = (byte)(strOrig[i] ^ roaster[i]);
			}
			
			return retVal;
		}

		public Hashtable GetTLVHash(byte [] byteData, int iDataLen)
		{
			int iIndex = 0;
			Hashtable retVal = new Hashtable();
			byte [] byteTemp = new byte[2];
			
			while (iIndex < iDataLen)
			{
				TLV tlv = new TLV();

				byteTemp[1] = byteData[iIndex++];
				byteTemp[0] = byteData[iIndex++];
				tlv.type = BitConverter.ToInt16(byteTemp,0);

				byteTemp[1] = byteData[iIndex++];
				byteTemp[0] = byteData[iIndex++];
				tlv.length = BitConverter.ToInt16(byteTemp,0);
				
				Array.Copy(byteData,iIndex,tlv.byteData,0,tlv.length);
				iIndex += tlv.length;

				retVal[tlv.type.ToString()] = tlv;
			}

			return retVal;
		}

		private void DispatchError(string strError)
		{
			if (OnError != null)
				OnError(strError);
		}

		public void AddBuddy(string strBuddy)
		{
			if (!m_socket.Connected && !m_bDCOnPurpose)
				HandleReconnect();
			else
			{
				byte iLen = (byte)strBuddy.Length;
				byte [] bName = new byte[iLen+1];
				bName[0] = iLen;

				Array.Copy(Encoding.Default.GetBytes(strBuddy),0,bName,1,iLen);
				SendSnacPacket(GetSNACHeader(0x3,0x04,0x0,0x04),bName);
			}
		}

		public void AddBuddies(string [] strBuddies)
		{
			if (!m_socket.Connected && !m_bDCOnPurpose)
				HandleReconnect();
			else
			{
				string strOutput = "";

				foreach (string strBuddy in strBuddies)
				{
					strOutput += Encoding.ASCII.GetChars(new byte [] { (byte)strBuddy.Length })[0];
					strOutput += strBuddy;
				}

				SendSnacPacket(GetSNACHeader(0x03,0x04,0x0,0x04),Encoding.Default.GetBytes(strOutput));
			}
		}

		public void Disconnect()
		{
			m_bDCOnPurpose = true;
			m_bAuthenticated = false;
			m_bTCPConnected = false;

			if (m_socket != null && m_socket.Connected)
			{
				m_socket.Shutdown(SocketShutdown.Both);
				m_socket.Close();
				
				if (OnDisconnect != null)
					OnDisconnect();
			}
		}
	}

}
