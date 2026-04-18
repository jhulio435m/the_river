<Global.Microsoft.VisualBasic.CompilerServices.DesignerGenerated()>
Partial Class FormLoading
    Inherits System.Windows.Forms.Form

    'Form reemplaza a Dispose para limpiar la lista de componentes.
    <System.Diagnostics.DebuggerNonUserCode()>
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
    <System.Diagnostics.DebuggerStepThrough()>
    Private Sub InitializeComponent()
        lblStatus = New Label()
        ProgressBar1 = New ProgressBar()
        SuspendLayout()
        ' 
        ' lblStatus
        ' 
        lblStatus.Font = New Font("MS Gothic", 12.75F, FontStyle.Bold)
        lblStatus.ForeColor = Color.Lime
        lblStatus.Location = New Point(0, 42)
        lblStatus.Name = "lblStatus"
        lblStatus.Size = New Size(277, 15)
        lblStatus.TabIndex = 0
        lblStatus.Text = "Texto"
        lblStatus.TextAlign = ContentAlignment.TopCenter
        ' 
        ' ProgressBar1
        ' 
        ProgressBar1.Location = New Point(89, 80)
        ProgressBar1.Name = "ProgressBar1"
        ProgressBar1.Size = New Size(97, 23)
        ProgressBar1.TabIndex = 1
        ' 
        ' FormLoading
        ' 
        AutoScaleDimensions = New SizeF(7F, 15F)
        AutoScaleMode = AutoScaleMode.Font
        BackColor = Color.Black
        ClientSize = New Size(276, 150)
        Controls.Add(ProgressBar1)
        Controls.Add(lblStatus)
        FormBorderStyle = FormBorderStyle.FixedDialog
        MaximizeBox = False
        MinimizeBox = False
        Name = "FormLoading"
        StartPosition = FormStartPosition.CenterScreen
        Text = "Iniciando sistema..."
        ResumeLayout(False)
    End Sub

    Friend WithEvents lblStatus As Label
    Friend WithEvents ProgressBar1 As ProgressBar
End Class