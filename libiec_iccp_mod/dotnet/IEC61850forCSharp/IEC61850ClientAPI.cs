/*
 *  IEC61850ClientAPI.cs
 *
 *  Copyright 2014 Michael Zillgith
 *
 *  This file is part of libIEC61850.
 *
 *  libIEC61850 is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  libIEC61850 is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with libIEC61850.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  See COPYING file for the complete license text.
 */
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Collections;

using IEC61850.Common;

namespace IEC61850
{
	namespace Client
	{
		public partial class IedConnection
		{
			/*************
            * MmsValue
            *************/
			[DllImport ("iec61850", CallingConvention=CallingConvention.Cdecl)]
			static extern IntPtr MmsValue_toString (IntPtr self);

			[DllImport ("iec61850", CallingConvention=CallingConvention.Cdecl)]
			static extern float MmsValue_toFloat (IntPtr self);

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern bool MmsValue_getBoolean (IntPtr self);

			[DllImport ("iec61850", CallingConvention=CallingConvention.Cdecl)]
			static extern UInt32 MmsValue_getBitStringAsInteger (IntPtr self);

			[DllImport ("iec61850", CallingConvention=CallingConvention.Cdecl)]
			static extern int MmsValue_getType (IntPtr self);
        
			[DllImport ("iec61850", CallingConvention=CallingConvention.Cdecl)]
			static extern void MmsValue_delete (IntPtr self);

			/****************
            * IedConnection
            ***************/

			[DllImport ("iec61850", CallingConvention=CallingConvention.Cdecl)]
			static extern IntPtr IedConnection_create ();

			[DllImport ("iec61850", CallingConvention=CallingConvention.Cdecl)]
			static extern void IedConnection_connect (IntPtr self, out int error, string hostname, int tcpPort);

			[DllImport ("iec61850", CallingConvention=CallingConvention.Cdecl)]
			static extern void IedConnection_abort (IntPtr self, out int error);

			[DllImport ("iec61850", CallingConvention=CallingConvention.Cdecl)]
			private static extern void IedConnection_release(IntPtr self, out int error);

			[DllImport ("iec61850", CallingConvention=CallingConvention.Cdecl)]
			private static extern void IedConnection_close(IntPtr self);

			[DllImport ("iec61850", CallingConvention=CallingConvention.Cdecl)]
			static extern IntPtr IedConnection_readObject (IntPtr self, out int error, string objectReference, int fc);

			[DllImport ("iec61850", CallingConvention=CallingConvention.Cdecl)]
			static extern void IedConnection_writeObject (IntPtr self, out int error, string dataAttributeReference, int fc, IntPtr value);

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern IntPtr IedConnection_getDataDirectory (IntPtr self, out int error, string dataReference);

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern IntPtr IedConnection_getDataDirectoryFC (IntPtr self, out int error, string dataReference);

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern IntPtr IedConnection_getLogicalNodeDirectory (IntPtr self, out int error, string logicalNodeReference, int acsiClass);
        
			[DllImport ("iec61850", CallingConvention=CallingConvention.Cdecl)]
			static extern IntPtr IedConnection_getServerDirectory (IntPtr self, out int error, bool getFileNames);

			[DllImport ("iec61850", CallingConvention=CallingConvention.Cdecl)]
			static extern IntPtr IedConnection_getLogicalDeviceDirectory (IntPtr self, out int error, string logicalDeviceName);


			private delegate void InternalConnectionClosedHandler (IntPtr parameter,IntPtr Iedconnection);

			public delegate void ConnectionClosedHandler (IedConnection connection);

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern void IedConnection_installConnectionClosedHandler (IntPtr self, InternalConnectionClosedHandler handler, IntPtr parameter);

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern IntPtr IedConnection_readDataSetValues (IntPtr self, out int error, string dataSetReference, IntPtr dataSet);

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern IntPtr IedConnection_createDataSet (IntPtr self, out int error, string dataSetReference, IntPtr dataSet);

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern void IedConnection_deleteDataSet (IntPtr self, out int error, string dataSetReference);

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern IntPtr IedConnection_getDataSetDirectory (IntPtr self, out int error, string dataSetReference, out bool isDeletable);

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern IntPtr IedConnection_getMmsConnection (IntPtr self);

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern IntPtr MmsConnection_getIsoConnectionParameters(IntPtr mmsConnection);

			/****************
        	* LinkedList
         	***************/
			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern IntPtr LinkedList_getNext (IntPtr self);

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern IntPtr LinkedList_getData (IntPtr self);

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern void LinkedList_destroy (IntPtr self);

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern IntPtr LinkedList_create ();

			[DllImport("iec61850", CallingConvention = CallingConvention.Cdecl)]
			static extern void LinkedList_add (IntPtr self, IntPtr data);

			private IntPtr connection;
			private InternalConnectionClosedHandler connectionClosedHandler;
			private ConnectionClosedHandler userProvidedHandler = null;

			public IedConnection ()
			{
				connection = IedConnection_create ();
			}

			public IsoConnectionParameters GetConnectionParameters ()
			{
				IntPtr mmsConnection = IedConnection_getMmsConnection(connection);

				IntPtr parameters = MmsConnection_getIsoConnectionParameters(mmsConnection);

				return new IsoConnectionParameters(parameters);
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public void Connect (string hostname, int tcpPort)
			{
				int error;

				IedConnection_connect (connection, out error, hostname, tcpPort);

				if (error != 0)
					throw new IedConnectionException ("Connect to " + hostname + ":" + tcpPort + " failed", error);
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public ControlObject CreateControlObject (string objectReference)
			{
				ControlObject controlObject = new ControlObject (objectReference, connection);

				return controlObject;
			}


			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public List<string> GetServerDirectory (bool fileDirectory)
			{
				int error;

				IntPtr linkedList = IedConnection_getServerDirectory (connection, out error, fileDirectory);

				if (error != 0)
					throw new IedConnectionException ("GetDeviceDirectory failed", error);

				IntPtr element = LinkedList_getNext (linkedList);

				List<string> newList = new List<string> ();

				while (element != IntPtr.Zero) {
					string ld = Marshal.PtrToStringAnsi (LinkedList_getData (element));

					newList.Add (ld);

					element = LinkedList_getNext (element);
				}

				LinkedList_destroy (linkedList);

				return newList;
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public List<string> GetLogicalDeviceDirectory (string logicalDeviceName)
			{
				int error;

				IntPtr linkedList = IedConnection_getLogicalDeviceDirectory (connection, out error, logicalDeviceName);

				if (error != 0)
					throw new IedConnectionException ("GetLogicalDeviceDirectory failed", error);

				IntPtr element = LinkedList_getNext (linkedList);

				List<string> newList = new List<string> ();

				while (element != IntPtr.Zero) {
					string ln = Marshal.PtrToStringAnsi (LinkedList_getData (element));

					newList.Add (ln);

					element = LinkedList_getNext (element);
				}

				LinkedList_destroy (linkedList);

				return newList;
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public List<string> GetLogicalNodeDirectory (string logicalNodeName, ACSIClass acsiClass)
			{
				int error;

				IntPtr linkedList = IedConnection_getLogicalNodeDirectory (connection, out error, logicalNodeName, (int)acsiClass);

				if (error != 0)
					throw new IedConnectionException ("GetLogicalNodeDirectory failed", error);

				IntPtr element = LinkedList_getNext (linkedList);

				List<string> newList = new List<string> ();

				while (element != IntPtr.Zero) {
					string dataObject = Marshal.PtrToStringAnsi (LinkedList_getData (element));

					newList.Add (dataObject);

					element = LinkedList_getNext (element);
				}

				LinkedList_destroy (linkedList);

				return newList;
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public List<string> GetDataDirectory (string dataReference)
			{
				int error;

				IntPtr linkedList = IedConnection_getDataDirectory (connection, out error, dataReference);

				if (error != 0)
					throw new IedConnectionException ("GetDataDirectory failed", error);

				IntPtr element = LinkedList_getNext (linkedList);

				List<string> newList = new List<string> ();

				while (element != IntPtr.Zero) {
					string dataObject = Marshal.PtrToStringAnsi (LinkedList_getData (element));

					newList.Add (dataObject);

					element = LinkedList_getNext (element);
				}

				LinkedList_destroy (linkedList);

				return newList;
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public List<string> GetDataDirectoryFC (string dataReference)
			{
				int error;

				IntPtr linkedList = IedConnection_getDataDirectoryFC (connection, out error, dataReference);

				if (error != 0)
					throw new IedConnectionException ("GetDataDirectoryFC failed", error);

				IntPtr element = LinkedList_getNext (linkedList);

				List<string> newList = new List<string> ();

				while (element != IntPtr.Zero) {
					string dataObject = Marshal.PtrToStringAnsi (LinkedList_getData (element));

					newList.Add (dataObject);

					element = LinkedList_getNext (element);
				}

				LinkedList_destroy (linkedList);

				return newList;
			}

			private IntPtr readObjectInternal (string objectReference, FunctionalConstraint fc)
			{
				int error;

				IntPtr mmsValue = IedConnection_readObject (connection, out error, objectReference, (int)fc); 

				if (error != 0)
					throw new IedConnectionException ("Reading value failed", error);

				if (mmsValue.ToInt32 () == 0)
					throw new IedConnectionException ("Variable not found on server", error);

				return mmsValue;
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public MmsValue ReadValue (String objectReference, FunctionalConstraint fc)
			{
				IntPtr value = readObjectInternal (objectReference, fc);

				return new MmsValue (value, true);
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public float ReadFloatValue (string objectReference, FunctionalConstraint fc)
			{
				IntPtr mmsValue = readObjectInternal (objectReference, fc);

				if (MmsValue_getType (mmsValue) != (int)MmsType.MMS_FLOAT)
					throw new IedConnectionException ("Result is not of type float", 0);

				float value = MmsValue_toFloat (mmsValue);

				MmsValue_delete (mmsValue);

				return value;
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public string ReadStringValue (string objectReference, FunctionalConstraint fc)
			{
				IntPtr mmsValue = readObjectInternal (objectReference, fc);

				if (!((MmsValue_getType (mmsValue) == (int)MmsType.MMS_VISIBLE_STRING) || (MmsValue_getType (mmsValue) == (int)MmsType.MMS_STRING))) {
					MmsValue_delete (mmsValue);
					throw new IedConnectionException ("Result is not of type string", 0);
				}

				IntPtr ptr = MmsValue_toString (mmsValue);

				string returnString = Marshal.PtrToStringAnsi (ptr);

				MmsValue_delete (mmsValue);

				return returnString;
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public Quality ReadQualityValue (string objectReference, FunctionalConstraint fc)
			{
				IntPtr mmsValue = readObjectInternal (objectReference, fc);

				if (MmsValue_getType (mmsValue) == (int)MmsType.MMS_BIT_STRING) {
					int bitStringValue = (int)MmsValue_getBitStringAsInteger (mmsValue);

					MmsValue_delete (mmsValue);
					return new Quality (bitStringValue);
				} else {
					MmsValue_delete (mmsValue);
					throw new IedConnectionException ("Result is not of type bit string(Quality)", 0);
				}
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public void WriteValue (string objectReference, FunctionalConstraint fc, MmsValue value)
			{
				int error;

				IedConnection_writeObject (connection, out error, objectReference, (int)fc, value.valueReference);

				if (error != 0)
					throw new IedConnectionException ("Write value failed", error);
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public void Abort ()
			{
				int error;

				IedConnection_abort (connection, out error);

				if (error != 0)
					throw new IedConnectionException ("Abort failed", error);
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public void Release ()
			{
				int error;

				IedConnection_release(connection, out error);

				if (error != 0)
					throw new IedConnectionException ("Release failed", error);
			}

			public void Close ()
			{
				IedConnection_close(connection);
			}

			private void MyConnectionClosedHandler (IntPtr parameter, IntPtr self)
			{
				if (userProvidedHandler != null)
					userProvidedHandler (this);
			}

			public void InstallConnectionClosedHandler (ConnectionClosedHandler handler)
			{
				connectionClosedHandler = new InternalConnectionClosedHandler (MyConnectionClosedHandler);

				userProvidedHandler = handler;

				IedConnection_installConnectionClosedHandler (connection, connectionClosedHandler, connection);
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public DataSet ReadDataSetValues (string dataSetReference, DataSet dataSet)
			{
				IntPtr nativeClientDataSet = IntPtr.Zero;

				if (dataSet != null)
					nativeClientDataSet = dataSet.getNativeInstance ();
     
				int error;

				nativeClientDataSet = IedConnection_readDataSetValues (connection, out error, dataSetReference, nativeClientDataSet);
                    
				if (error != 0)
					throw new IedConnectionException ("Reading data set failed", error);

				if (dataSet == null)
					dataSet = new DataSet (nativeClientDataSet);

				return dataSet;
			}

			public void CreateDataSet (string dataSetReference, List<string> dataSetElements)
			{
				IntPtr linkedList = LinkedList_create ();

				foreach (string dataSetElement in dataSetElements) {
					IntPtr handle = System.Runtime.InteropServices.Marshal.StringToHGlobalAuto (dataSetElement);

					LinkedList_add (linkedList, handle);
				}

				int error;

				IedConnection_createDataSet (connection, out error, dataSetReference, linkedList);

				LinkedList_destroy (linkedList);

				if (error != 0)
					throw new IedConnectionException ("Failed to create data set", error);

			}

			public void DeleteDataSet (string dataSetReference)
			{
				int error;

				IedConnection_deleteDataSet (connection, out error, dataSetReference);

				if (error != 0)
					throw new IedConnectionException ("Failed to delete data set", error);
			}

			/// <exception cref="IedConnectionException">This exception is thrown if there is a connection or service error</exception>
			public List<string> GetDataSetDirectory (string dataSetReference)
			{
				int error;
				bool isDeletable;

				IntPtr linkedList = IedConnection_getDataSetDirectory (connection, out error, dataSetReference, out isDeletable);

				if (error != 0)
					throw new IedConnectionException ("getDataSetDirectory failed", error);

				IntPtr element = LinkedList_getNext (linkedList);

				List<string> newList = new List<string> ();

				while (element != IntPtr.Zero) {
					string dataObject = Marshal.PtrToStringAnsi (LinkedList_getData (element));

					newList.Add (dataObject);

					element = LinkedList_getNext (element);
				}

				LinkedList_destroy (linkedList);

				return newList;
			}
		}

		public class IedConnectionException : Exception
		{

			private int errorCode;

			public IedConnectionException (string message, int errorCode) : base(message)
			{
				this.errorCode = errorCode;
			}

			public IedConnectionException (string message) : base(message)
			{
				this.errorCode = 0;
			}

			public int GetErrorCode ()
			{
				return this.errorCode;
			}

			public IedClientError GetIedClientError ()
			{
				return (IedClientError)this.errorCode;
			}
		}

		public enum IedClientError
		{
			/* general errors */

			/** No error occurred - service request has been successful */
			IED_ERROR_OK = 0,

			/** The service request can not be executed because the client is not yet connected */
			IED_ERROR_NOT_CONNECTED = 1,

			/** Connect service not execute because the client is already connected */
			IED_ERROR_ALREADY_CONNECTED = 2,

			/** The service request can not be executed caused by a loss of connection */
			IED_ERROR_CONNECTION_LOST = 3,

			/** The service or some given parameters are not supported by the client stack or by the server */
			IED_ERROR_SERVICE_NOT_SUPPORTED = 4,

			/** Connection rejected by server */
			IED_ERROR_CONNECTION_REJECTED = 5,

			/* client side errors */

			/** API function has been called with an invalid argument */
			IED_ERROR_USER_PROVIDED_INVALID_ARGUMENT = 10,

			IED_ERROR_ENABLE_REPORT_FAILED_DATASET_MISMATCH = 11,

			/** The object provided object reference is invalid (there is a syntactical error). */
			IED_ERROR_OBJECT_REFERENCE_INVALID = 12,

			/** Received object is of unexpected type */
			IED_ERROR_UNEXPECTED_VALUE_RECEIVED = 13,

			/* service error - error reported by server */

			/** The communication to the server failed with a timeout */
			IED_ERROR_TIMEOUT = 20,

			/** The server rejected the access to the requested object/service due to access control */
			IED_ERROR_ACCESS_DENIED = 21,

			/** The server reported that the requested object does not exist */
			IED_ERROR_OBJECT_DOES_NOT_EXIST = 22,

			/** The server reported that the requested object already exists */
			IED_ERROR_OBJECT_EXISTS = 23,

			/** The server does not support the requested access method */
			IED_ERROR_OBJECT_ACCESS_UNSUPPORTED = 24,

			/* unknown error */
			IED_ERROR_UNKNOWN = 99
		}  
	}

	namespace Common
	{
	
		[Flags]
		public enum TriggerOptions {
			NONE = 0,
			DATA_CHANGED = 1,
			QUALITY_CHANGED = 2,
			DATA_UPDATE = 4,
			INTEGRITY = 8,
			GI = 16
		}

		[Flags]
		public enum ReportOptions {
			NONE = 0,
			SEQ_NUM = 1,
			TIME_STAMP = 2,
			REASON_FOR_INCLUSION = 4,
			DATA_SET = 8,
			DATA_REFERENCE = 16,
			BUFFER_OVERFLOW = 32,
			ENTRY_ID = 64,
			CONF_REV = 128
		}

		public enum Validity
		{
			GOOD = 0,
			INVALID = 1,
			RESERVED = 2,
			QUESTIONABLE = 3
		}

		public class Quality
		{

			private UInt16 value;

			public Quality (int bitStringValue)
			{
				value = (UInt16)bitStringValue;
			}

			public Quality ()
			{
				value = 0;
			}

			public Validity GetValidity ()
			{
				int qualityVal = value & 0x3;

				return (Validity)qualityVal;
			}

			public void SetValidity (Validity validity)
			{
				value = (UInt16)(value & 0xfffc);

				value += (ushort)validity;
			}
		}

		public enum ACSIClass
		{
			ACSI_CLASS_DATA_OBJECT,
			ACSI_CLASS_DATA_SET,
			ACSI_CLASS_BRCB,
			ACSI_CLASS_URCB,
			ACSI_CLASS_LCB,
			ACSI_CLASS_LOG,
			ACSI_CLASS_SGCB,
			ACSI_CLASS_GoCB,
			ACSI_CLASS_GsCB,
			ACSI_CLASS_MSVCB,
			ACSI_CLASS_USVCB
		}

		public enum FunctionalConstraint
		{
			/** Status information */
			ST = 0,
			/** Measurands - analog values */
			MX = 1,
			/** Setpoint */
			SP = 2,
			/** Substitution */
			SV = 3,
			/** Configuration */
			CF = 4,
			/** Description */
			DC = 5,
			/** Setting group */
			SG = 6,
			/** Setting group editable */
			SE = 7,
			/** Service response / Service tracking */
			SR = 8,
			/** Operate received */
			OR = 9,
			/** Blocking */
			BL = 10,
			/** Extended definition */
			EX = 11,
			/** Control */
			CO = 12,
			ALL = 99,
			NONE = -1
		}

	}
}
