Imports System.IO
Imports System.Diagnostics
Imports System.Net.Sockets

Public Class FormLoading
    Private _torProcess As Process

    Private Async Sub FormLoading_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        ' --- CONFIGURACIÓN ESTÉTICA ---
        Me.ControlBox = False
        Me.StartPosition = FormStartPosition.CenterScreen

        ' Configuración de la barra para modo continuo
        ProgressBar1.Style = ProgressBarStyle.Continuous
        ProgressBar1.Minimum = 0
        ProgressBar1.Maximum = 100
        ProgressBar1.Value = 0

        ' --- PASO 1: LANZAR TOR ---
        Try
            ActualizarEstado("Iniciando motor Tor...", 15)
            StartTorInvisible()
            ActualizarEstado("Motor Tor en ejecución.", 30)
        Catch ex As Exception
            MsgBox("Error al lanzar Tor: " & ex.Message, MsgBoxStyle.Critical)
            Application.Exit() : Return
        End Try

        ' --- PASO 2: ESPERAR TÚNEL LOCAL ---
        ActualizarEstado("Abriendo túnel de anonimato...", 45)
        Dim torListo = Await WaitForTor()

        If Not torListo Then
            MsgBox("El motor Tor no arrancó correctamente.", MsgBoxStyle.Critical)
            Application.Exit() : Return
        End If
        ActualizarEstado("Túnel local establecido.", 65)

        ' --- PASO 3: PRUEBA DE CONEXIÓN REAL ---
        ActualizarEstado("Conectando al círculo...", 80)
        Dim servidorDisponible = Await TestOnionConnection()

        If servidorDisponible Then
            ActualizarEstado("...", 100)
            Await Task.Delay(800) ' Breve pausa para que el usuario vea el 100%

            Dim chatForm As New Form36()
            chatForm.Show()
            Me.Hide()
        Else
            MsgBox("El servidor .onion no responde. Asegúrate de que el Círculo esté activo.", MsgBoxStyle.Exclamation)
            Application.Exit()
        End If
    End Sub

    ' Método auxiliar para actualizar la UI sin bloqueos
    Private Sub ActualizarEstado(texto As String, porcentaje As Integer)
        lblStatus.Text = texto
        ProgressBar1.Value = porcentaje
        ' Forzamos el redibujado
        lblStatus.Refresh()
        ProgressBar1.Refresh()
    End Sub

    Private Async Function TestOnionConnection() As Task(Of Boolean)
        Try
            Using client As New TcpClient()
                Await client.ConnectAsync("127.0.0.1", 9050)
                Dim stream = client.GetStream()

                Dim handshake As Byte() = {&H5, &H1, &H0}
                Await stream.WriteAsync(handshake, 0, handshake.Length)
                Dim resp(1) As Byte
                Await stream.ReadAsync(resp, 0, resp.Length)

                Dim onionAddr = "3k4kzzkhiy6oyitin3g3wuy7hs6sf7tmcqdipe2vwaqxfyiggedltiid.onion"
                Dim destAddr As Byte() = System.Text.Encoding.ASCII.GetBytes(onionAddr)
                Dim request As New List(Of Byte) From {&H5, &H1, &H0, &H3}
                request.Add(CByte(destAddr.Length))
                request.AddRange(destAddr)
                request.Add(0)
                request.Add(80)

                Dim reqArray = request.ToArray()
                Await stream.WriteAsync(reqArray, 0, reqArray.Length)

                Dim reply(9) As Byte
                Await stream.ReadAsync(reply, 0, reply.Length)

                Return (reply(1) = &H0)
            End Using
        Catch
            Return False
        End Try
    End Function

    Private Sub StartTorInvisible()
        Dim torDir As String = Path.Combine(Application.StartupPath, "TorBin")
        Dim torPath As String = Path.Combine(torDir, "tor.exe")

        If Not File.Exists(torPath) Then
            Throw New FileNotFoundException("No se encontró el motor Tor.")
        End If

        Dim startInfo As New ProcessStartInfo()
        startInfo.FileName = torPath
        startInfo.WorkingDirectory = torDir
        startInfo.Arguments = "--SocksPort 9050 --DataDirectory tor_data --GeoIPFile geoip --GeoIPv6File geoip6"
        startInfo.WindowStyle = ProcessWindowStyle.Hidden
        startInfo.CreateNoWindow = True
        startInfo.UseShellExecute = False

        _torProcess = Process.Start(startInfo)
    End Sub

    Private Async Function WaitForTor() As Task(Of Boolean)
        Dim intentos As Integer = 0
        While intentos < 60
            Dim exito As Boolean = False
            Try
                Using client As New TcpClient()
                    Await client.ConnectAsync("127.0.0.1", 9050)
                    exito = True
                End Using
            Catch
                exito = False
            End Try

            If exito Then
                Return True
            Else
                Await Task.Delay(1000)
                intentos += 1
            End If
        End While
        Return False
    End Function

    Private Sub FormLoading_FormClosing(sender As Object, e As FormClosingEventArgs) Handles MyBase.FormClosing
        ' Si se cierra el loading antes de pasar al chat, matamos la app
        If Me.Visible = True Then Environment.Exit(0)
    End Sub
End Class