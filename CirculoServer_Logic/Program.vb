Imports System.Net
Imports System.Net.Sockets
Imports System.IO
Imports System.Collections.Concurrent

Module Program
    ' Usamos Dictionary para poder eliminar al usuario por su ID único cuando se desconecte
    Private Clients As New ConcurrentDictionary(Of Guid, StreamWriter)()

    Sub Main()
        ' El puerto 8888 debe coincidir con el "HiddenServicePort" de tu torrc
        Dim listener As New TcpListener(IPAddress.Any, 8888)
        listener.Start()

        Console.Title = "Cerebro del Circulo - Servidor"
        Console.WriteLine("========================================")
        Console.WriteLine("    SERVIDOR DEL CIRCULO - MODO TOR     ")
        Console.WriteLine("========================================")
        Console.WriteLine("Estado: Activo y escuchando en puerto 8888...")

        While True
            Try
                Dim client As TcpClient = listener.AcceptTcpClient()
                Task.Run(Sub() HandleClient(client))
            Catch ex As Exception
                Console.WriteLine("Error de conexión: " & ex.Message)
            End Try
        End While
    End Sub

    Private Sub HandleClient(client As TcpClient)
        ' Generamos un ID único para esta conexión
        Dim clientId As Guid = Guid.NewGuid()
        Dim stream = client.GetStream()
        Dim reader As New StreamReader(stream)
        Dim writer As New StreamWriter(stream) With {.AutoFlush = True}

        ' Añadimos al cliente a la lista activa
        Clients.TryAdd(clientId, writer)
        Console.WriteLine("[+] Nueva conexión establecida (ID: " & clientId.ToString().Substring(0, 8) & ")")

        Try
            While True
                Dim message = reader.ReadLine()
                If message IsNot Nothing Then
                    Console.WriteLine(">> " & message)
                    Broadcast(message)
                Else
                    Exit While ' El cliente cerró la conexión limpiamente
                End If
            End While
        Catch
            ' Error de red o cierre forzado
        Finally
            ' LIMPIEZA: Eliminamos al cliente de la lista para no gastar recursos
            Dim removedWriter As StreamWriter = Nothing
            Clients.TryRemove(clientId, removedWriter)
            client.Close()
            Console.WriteLine("[-] Conexión cerrada (ID: " & clientId.ToString().Substring(0, 8) & ")")
        End Try
    End Sub

    Private Sub Broadcast(msg As String)
        ' Enviamos el mensaje a todos los que están en el diccionario
        For Each kvp In Clients
            Try
                ' kvp.Value es el StreamWriter
                kvp.Value.WriteLine(msg)
            Catch
                ' Si falla, probablemente el cliente ya no está, se limpiará en su propio hilo
            End Try
        Next
    End Sub
End Module