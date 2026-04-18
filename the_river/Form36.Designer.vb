<Global.Microsoft.VisualBasic.CompilerServices.DesignerGenerated()> _
Partial Class Form36
    Inherits System.Windows.Forms.Form

    'Form reemplaza a Dispose para limpiar la lista de componentes.
    <System.Diagnostics.DebuggerNonUserCode()> _
    Protected Overrides Sub Dispose(ByVal disposing As Boolean)
        Try
            If disposing AndAlso components IsNot Nothing Then
                components.Dispose()
            End If
        Finally
            MyBase.Dispose(disposing)
        End Try
    End Sub

    'Requerido por el Diseñador de Windows Forms
    Private components As System.ComponentModel.IContainer

    'NOTA: el Diseñador de Windows Forms necesita el siguiente procedimiento
    'Se puede modificar usando el Diseñador de Windows Forms.  
    'No lo modifique con el editor de código.
    <System.Diagnostics.DebuggerStepThrough()> _
    Private Sub InitializeComponent()
        Dim resources As System.ComponentModel.ComponentResourceManager = New System.ComponentModel.ComponentResourceManager(GetType(Form36))
        Label1 = New Label()
        LabelActiveUsers = New Label()
        Label2 = New Label()
        PictureBox1 = New PictureBox()
        PictureBox3 = New PictureBox()
        PictureBox2 = New PictureBox()
        LabelUserName = New Label()
        Label3 = New Label()
        TextBox1 = New TextBox()
        ListBoxChat = New ListBox()
        PictureBox4 = New PictureBox()
        ListBoxActives = New ListBox()
        CType(PictureBox1, ComponentModel.ISupportInitialize).BeginInit()
        CType(PictureBox3, ComponentModel.ISupportInitialize).BeginInit()
        CType(PictureBox2, ComponentModel.ISupportInitialize).BeginInit()
        CType(PictureBox4, ComponentModel.ISupportInitialize).BeginInit()
        SuspendLayout()
        ' 
        ' Label1
        ' 
        Label1.AutoSize = True
        Label1.BackColor = Color.FromArgb(CByte(0), CByte(0), CByte(192))
        Label1.Font = New Font("MS Gothic", 12.75F, FontStyle.Bold, GraphicsUnit.Point, CByte(0))
        Label1.ForeColor = Color.White
        Label1.Location = New Point(5, 12)
        Label1.Name = "Label1"
        Label1.Size = New Size(128, 17)
        Label1.TabIndex = 0
        Label1.Text = "Active Users"
        ' 
        ' LabelActiveUsers
        ' 
        LabelActiveUsers.AutoSize = True
        LabelActiveUsers.BackColor = Color.FromArgb(CByte(0), CByte(0), CByte(192))
        LabelActiveUsers.Font = New Font("MS Gothic", 12.75F, FontStyle.Bold, GraphicsUnit.Point, CByte(0))
        LabelActiveUsers.ForeColor = Color.White
        LabelActiveUsers.Location = New Point(139, 12)
        LabelActiveUsers.Name = "LabelActiveUsers"
        LabelActiveUsers.Size = New Size(18, 17)
        LabelActiveUsers.TabIndex = 1
        LabelActiveUsers.Text = "0"
        ' 
        ' Label2
        ' 
        Label2.AutoSize = True
        Label2.BackColor = Color.FromArgb(CByte(0), CByte(0), CByte(192))
        Label2.Font = New Font("Yu Gothic", 14.25F, FontStyle.Regular, GraphicsUnit.Point, CByte(0))
        Label2.ForeColor = Color.White
        Label2.Location = New Point(308, 9)
        Label2.Name = "Label2"
        Label2.Size = New Size(123, 25)
        Label2.TabIndex = 2
        Label2.Text = "THE CIRCLE"
        ' 
        ' PictureBox1
        ' 
        PictureBox1.BackColor = Color.FromArgb(CByte(0), CByte(0), CByte(192))
        PictureBox1.Location = New Point(-7, -1)
        PictureBox1.Name = "PictureBox1"
        PictureBox1.Size = New Size(727, 44)
        PictureBox1.TabIndex = 3
        PictureBox1.TabStop = False
        ' 
        ' PictureBox3
        ' 
        PictureBox3.BackColor = Color.FromArgb(CByte(0), CByte(0), CByte(192))
        PictureBox3.Location = New Point(-7, 385)
        PictureBox3.Name = "PictureBox3"
        PictureBox3.Size = New Size(731, 22)
        PictureBox3.TabIndex = 5
        PictureBox3.TabStop = False
        ' 
        ' PictureBox2
        ' 
        PictureBox2.BackColor = Color.FromArgb(CByte(0), CByte(0), CByte(192))
        PictureBox2.Location = New Point(-7, 439)
        PictureBox2.Name = "PictureBox2"
        PictureBox2.Size = New Size(727, 22)
        PictureBox2.TabIndex = 6
        PictureBox2.TabStop = False
        ' 
        ' LabelUserName
        ' 
        LabelUserName.AutoSize = True
        LabelUserName.Font = New Font("MS Gothic", 12F, FontStyle.Bold, GraphicsUnit.Point, CByte(0))
        LabelUserName.ForeColor = Color.FromArgb(CByte(192), CByte(0), CByte(192))
        LabelUserName.Location = New Point(5, 413)
        LabelUserName.Name = "LabelUserName"
        LabelUserName.Size = New Size(0, 16)
        LabelUserName.TabIndex = 7
        LabelUserName.TextAlign = ContentAlignment.MiddleCenter
        ' 
        ' Label3
        ' 
        Label3.AutoSize = True
        Label3.Font = New Font("MS Gothic", 12F, FontStyle.Bold, GraphicsUnit.Point, CByte(0))
        Label3.ForeColor = Color.FromArgb(CByte(0), CByte(192), CByte(0))
        Label3.Location = New Point(99, 413)
        Label3.Name = "Label3"
        Label3.Size = New Size(34, 16)
        Label3.TabIndex = 8
        Label3.Text = "-->"
        ' 
        ' TextBox1
        ' 
        TextBox1.BackColor = SystemColors.InactiveCaptionText
        TextBox1.BorderStyle = BorderStyle.None
        TextBox1.Font = New Font("MS Gothic", 12F, FontStyle.Bold, GraphicsUnit.Point, CByte(0))
        TextBox1.ForeColor = Color.FromArgb(CByte(192), CByte(0), CByte(192))
        TextBox1.Location = New Point(129, 413)
        TextBox1.Multiline = True
        TextBox1.Name = "TextBox1"
        TextBox1.Size = New Size(591, 24)
        TextBox1.TabIndex = 9
        ' 
        ' ListBoxChat
        ' 
        ListBoxChat.BackColor = Color.Black
        ListBoxChat.BorderStyle = BorderStyle.None
        ListBoxChat.Font = New Font("MS Gothic", 12F, FontStyle.Bold, GraphicsUnit.Point, CByte(0))
        ListBoxChat.ForeColor = Color.Lime
        ListBoxChat.FormattingEnabled = True
        ListBoxChat.Location = New Point(139, 46)
        ListBoxChat.Name = "ListBoxChat"
        ListBoxChat.Size = New Size(581, 336)
        ListBoxChat.TabIndex = 10
        ' 
        ' PictureBox4
        ' 
        PictureBox4.BackColor = Color.LightGray
        PictureBox4.Location = New Point(123, 43)
        PictureBox4.Name = "PictureBox4"
        PictureBox4.Size = New Size(10, 339)
        PictureBox4.TabIndex = 11
        PictureBox4.TabStop = False
        ' 
        ' ListBoxActives
        ' 
        ListBoxActives.BackColor = Color.Black
        ListBoxActives.BorderStyle = BorderStyle.None
        ListBoxActives.Font = New Font("MS Gothic", 11.25F, FontStyle.Bold, GraphicsUnit.Point, CByte(0))
        ListBoxActives.ForeColor = Color.Lime
        ListBoxActives.FormattingEnabled = True
        ListBoxActives.ItemHeight = 15
        ListBoxActives.Location = New Point(5, 59)
        ListBoxActives.Name = "ListBoxActives"
        ListBoxActives.Size = New Size(116, 285)
        ListBoxActives.TabIndex = 12
        ' 
        ' Form36
        ' 
        AutoScaleDimensions = New SizeF(7F, 15F)
        AutoScaleMode = AutoScaleMode.Font
        BackColor = Color.Black
        ClientSize = New Size(720, 462)
        Controls.Add(ListBoxActives)
        Controls.Add(PictureBox4)
        Controls.Add(ListBoxChat)
        Controls.Add(TextBox1)
        Controls.Add(Label3)
        Controls.Add(LabelUserName)
        Controls.Add(PictureBox2)
        Controls.Add(PictureBox3)
        Controls.Add(Label2)
        Controls.Add(LabelActiveUsers)
        Controls.Add(Label1)
        Controls.Add(PictureBox1)
        Icon = CType(resources.GetObject("$this.Icon"), Icon)
        MaximizeBox = False
        Name = "Form36"
        Text = "the river <3>"
        CType(PictureBox1, ComponentModel.ISupportInitialize).EndInit()
        CType(PictureBox3, ComponentModel.ISupportInitialize).EndInit()
        CType(PictureBox2, ComponentModel.ISupportInitialize).EndInit()
        CType(PictureBox4, ComponentModel.ISupportInitialize).EndInit()
        ResumeLayout(False)
        PerformLayout()
    End Sub

    Friend WithEvents Label1 As Label
    Friend WithEvents LabelActiveUsers As Label
    Friend WithEvents Label2 As Label
    Friend WithEvents PictureBox1 As PictureBox
    Friend WithEvents PictureBox3 As PictureBox
    Friend WithEvents PictureBox2 As PictureBox
    Friend WithEvents LabelUserName As Label
    Friend WithEvents Label3 As Label
    Friend WithEvents TextBox1 As TextBox
    Friend WithEvents ListBoxChat As ListBox
    Friend WithEvents PictureBox4 As PictureBox
    Friend WithEvents ListBoxActives As ListBox
End Class
