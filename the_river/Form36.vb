Imports System.Net.Sockets
Imports System.IO
Imports System.Text
Imports System.Collections.Concurrent
Imports System.Threading.Tasks
Imports System.Diagnostics

Public Class Form36
    ' --- PROPIEDADES DE RED ---
    Private _clientSocket As TcpClient
    Private _reader As StreamReader
    Private _writer As StreamWriter

    ' El Proxy ya está corriendo gracias al FormLoading
    Private ReadOnly _torProxyHost As String = "127.0.0.1"
    Private ReadOnly _torProxyPort As Integer = 9050

    ' Dirección del servidor de tu amigo
    Private ReadOnly _onionAddress As String = "3k4kzzkhiy6oyitin3g3wuy7hs6sf7tmcqdipe2vwaqxfyiggedltiid.onion"
    Private ReadOnly _port As Integer = 80

    ' --- PROPIEDADES DE UI ---
    Private WithEvents TimerUpdateUI As New System.Windows.Forms.Timer()
    Private _userName As String = ""
    Private ReadOnly _formUsers As New ConcurrentDictionary(Of String, Byte)()
    Private _needsUserListUpdate As Boolean = False

    ' --- INICIO ---
    Private Async Sub Form36_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        ' 1. Pedir Nickname con manejo de salida
        Dim nick As String = ""

        ' Usamos una variable auxiliar para capturar el resultado del InputBox
        Dim inputResult = Microsoft.VisualBasic.InputBox("El túnel es estable. Introduce tu Nickname:", "The Circle")

        ' Si el usuario pulsa "Cancelar" o la "X", inputResult será "" (pero el sistema lo distingue)
        ' En VB, InputBox devuelve una cadena vacía si se cancela. 
        ' Para una validación real de "Cancelar", comprobamos si es String.Empty
        If String.IsNullOrEmpty(inputResult) Then
            ' El usuario no quiere entrar, cerramos todo de raíz
            FinalizarTodo()
            Return
        End If

        ' Si escribió espacios o está vacío pero no canceló, insistimos o cerramos
        nick = inputResult.Trim()
        If nick = "" Then
            MsgBox("El Nickname no puede estar vacío.", MsgBoxStyle.Exclamation)
            ' Reiniciamos el proceso de carga para que vuelva a pedirlo o salga
            Form36_Load(sender, e)
            Return
        End If

        _userName = nick
        LabelUserName.Text = _userName
        _formUsers.TryAdd(_userName, 0)
        UpdateUserUI()

        TimerUpdateUI.Start()

        ' 2. Conectar
        Await ConnectToCircle()
    End Sub

    ' --- CIERRE SEGURO ---
    Private Sub FinalizarTodo()
        Try
            ' Intentamos avisar al servidor de nuestra salida de forma proactiva
            If _writer IsNot Nothing Then
                _writer.WriteLine("[LEAVE]:" & _userName)
                _writer.Flush()
            End If
        Catch
            ' Si falla (ej. internet caído), procedemos con el cierre igualmente
        End Try

        ' Matar el proceso actual y todos sus hilos (incluyendo tor.exe)
        Application.Exit()
        Environment.Exit(0)
    End Sub

    ' --- LÓGICA DE CONEXIÓN (Mantenemos la negociación SOCKS5) ---
    Private Async Function ConnectToCircle() As Task
        Try
            _clientSocket = New TcpClient()
            Await _clientSocket.ConnectAsync(_torProxyHost, _torProxyPort)
            Dim stream = _clientSocket.GetStream()

            ' Handshake SOCKS5
            Dim handshake As Byte() = {&H5, &H1, &H0}
            Await stream.WriteAsync(handshake, 0, handshake.Length)
            Dim resp(1) As Byte
            Await stream.ReadAsync(resp, 0, resp.Length)

            ' Solicitud de conexión al .onion
            Dim destAddr As Byte() = Encoding.ASCII.GetBytes(_onionAddress)
            Dim request As New List(Of Byte) From {&H5, &H1, &H0, &H3}
            request.Add(CByte(destAddr.Length))
            request.AddRange(destAddr)
            request.Add(CByte((_port >> 8) And &HFF))
            request.Add(CByte(_port And &HFF))

            Dim reqArray = request.ToArray()
            Await stream.WriteAsync(reqArray, 0, reqArray.Length)

            Dim reply(9) As Byte
            Await stream.ReadAsync(reply, 0, reply.Length)

            If reply(1) = &H0 Then
                _reader = New StreamReader(stream)
                _writer = New StreamWriter(stream) With {.AutoFlush = True}

                ' Iniciar escucha de mensajes en segundo plano
                Dim listenerTask = Task.Run(AddressOf ListenForMessages)

                Await SendSystemCommand("[JOIN]:" & _userName)
            Else
                AddMessageToListBox("El servidor .onion no está disponible.")
            End If
        Catch ex As Exception
            AddMessageToListBox("Error de red: " & ex.Message)
        End Try
    End Function

    ' --- COMUNICACIÓN Y PROCESAMIENTO ---
    Private Async Function ListenForMessages() As Task
        Dim hasError As Boolean = False
        Try
            While Not hasError
                Dim line = Await _reader.ReadLineAsync()
                If line IsNot Nothing Then
                    ProcessLine(line)
                Else
                    hasError = True
                End If
            End While
        Catch
            hasError = True
        End Try

        If hasError Then
            Me.BeginInvoke(Sub() AddMessageToListBox("!!! CONEXIÓN PERDIDA !!!"))
        End If
    End Function

    Private Sub ProcessLine(line As String)
        If line.StartsWith("[") Then
            Dim parts = line.Split(":"c)
            If parts.Length >= 2 Then
                Dim targetUser = parts(1)
                If targetUser <> _userName Then HandleCommand(parts(0), targetUser)
            End If
        Else
            Me.BeginInvoke(Sub() AddMessageToListBox(line))
        End If
    End Sub

    ' --- PROCESAMIENTO DE COMANDOS CORREGIDO ---
    Private Sub HandleCommand(cmd As String, user As String)
        Select Case cmd
            Case "[JOIN]"
                ' Solo notificamos si el usuario no estaba ya (evita spam de reconexión)
                If _formUsers.TryAdd(user, 0) Then
                    _needsUserListUpdate = True
                    Me.BeginInvoke(Sub() AddMessageToListBox(user & " se ha unido."))
                    ' Notificamos nuestra presencia al nuevo integrante
                    Task.Run(Function() SendSystemCommand("[ALIVE]:" & _userName))
                End If

            Case "[ALIVE]"
                ' Registro silencioso de usuarios ya presentes
                If _formUsers.TryAdd(user, 0) Then _needsUserListUpdate = True

            Case "[LEAVE]"
                ' --- FILTRO PARA EVITAR DOBLE MENSAJE ---
                Dim dummy As Byte
                ' TryRemove devuelve True SOLAMENTE la primera vez que se elimina al usuario
                If _formUsers.TryRemove(user, dummy) Then
                    _needsUserListUpdate = True
                    Me.BeginInvoke(Sub() AddMessageToListBox(user & " ha salido."))
                End If
        End Select
    End Sub

    Private Async Function SendChatMessage(text As String) As Task
        If _writer Is Nothing Then Return
        Try
            Dim finalMsg = _userName & ": " & text
            Await _writer.WriteLineAsync(finalMsg)
        Catch
            AddMessageToListBox("Error al enviar.")
        End Try
    End Function

    Private Async Function SendSystemCommand(command As String) As Task
        Try
            If _writer IsNot Nothing Then Await _writer.WriteLineAsync(command)
        Catch
        End Try
    End Function

    ' --- INTERFAZ DE USUARIO ---
    Private Sub TimerUpdateUI_Tick(sender As Object, e As EventArgs) Handles TimerUpdateUI.Tick
        If _needsUserListUpdate Then
            UpdateUserUI()
            _needsUserListUpdate = False
        End If
    End Sub

    Private Sub UpdateUserUI()
        If Me.InvokeRequired Then
            Me.BeginInvoke(Sub() UpdateUserUI()) : Return
        End If
        ListBoxActives.Items.Clear()
        For Each user In _formUsers.Keys : ListBoxActives.Items.Add(user) : Next
        LabelActiveUsers.Text = _formUsers.Count.ToString()
    End Sub

    Private Sub AddMessageToListBox(ByVal message As String)
        If ListBoxChat.InvokeRequired Then
            ListBoxChat.BeginInvoke(Sub() AddMessageToListBox(message))
        Else
            ListBoxChat.Items.Add(message)
            ListBoxChat.TopIndex = ListBoxChat.Items.Count - 1
        End If
    End Sub

    Private Sub TextBox1_KeyDown(sender As Object, e As KeyEventArgs) Handles TextBox1.KeyDown
        If e.KeyCode = Keys.Enter Then
            Dim msgText = TextBox1.Text.Trim()
            If msgText <> "" Then
                Dim t = Task.Run(Function() SendChatMessage(msgText))
                TextBox1.Clear()
            End If
            e.SuppressKeyPress = True
        End If
    End Sub

    ' --- CIERRE SEGURO ---
    Private Sub Form36_FormClosing(sender As Object, e As FormClosingEventArgs) Handles Me.FormClosing
        FinalizarTodo()
    End Sub
End Class