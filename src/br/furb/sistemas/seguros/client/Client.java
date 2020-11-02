package br.furb.sistemas.seguros.client;

import java.io.File;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.graphics.Rectangle;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Monitor;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;

import br.furb.sistemas.seguros.aes.AesCrypt;

public class Client extends Composite {

	private File inputFile;
	private Text edDest;
	private Text edCrypt;

	public static void main(String[] args) {
		Display display = Display.getDefault();
		Shell shell = new Shell(display);
		shell.setLayout(new GridLayout(1, false));
		shell.setText("Criptografia AES");
		new Client(shell, SWT.NONE);

		Monitor primary = display.getPrimaryMonitor();
		Rectangle bounds = primary.getBounds();
		Rectangle rect = shell.getBounds();

		int x = bounds.x + (bounds.width - rect.width) / 2;
		int y = bounds.y + (bounds.height - rect.height) / 2;

		shell.setLocation(x, y);
		shell.pack();
		shell.open();
		while (!shell.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
		display.dispose();
	}

	/**
	 * Create the composite.
	 * 
	 * @param parent
	 * @param style
	 */
	public Client(Composite parent, int style) {
		super(parent, style);
		setToolTipText("");

		Text edFileName = new Text(this, SWT.BORDER);
		edFileName.setEnabled(false);
		edFileName.setBounds(132, 12, 453, 21);

		Button btFileChooser = new Button(this, SWT.NONE);
		btFileChooser.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				JFileChooser chooser = new JFileChooser();
				int returnVal = chooser.showOpenDialog(null);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					inputFile = chooser.getSelectedFile();
					edFileName.setText(inputFile.getPath());
				}
			}
		});
		btFileChooser.setBounds(588, 11, 76, 23);
		btFileChooser.setText("Selecionar");

		Label lblNewLabel = new Label(this, SWT.NONE);
		lblNewLabel.setBounds(7, 15, 119, 15);
		lblNewLabel.setText("Arquivo a criptografar:");

		Label lblNewLabel_1 = new Label(this, SWT.NONE);
		lblNewLabel_1.setBounds(22, 39, 104, 15);
		lblNewLabel_1.setText("Arquivo de destino:");

		edDest = new Text(this, SWT.BORDER);
		edDest.setBounds(132, 36, 531, 21);

		Label lblNewLabel_1_1 = new Label(this, SWT.NONE);
		lblNewLabel_1_1.setAlignment(SWT.RIGHT);
		lblNewLabel_1_1.setText("Chave de criptografia:");
		lblNewLabel_1_1.setBounds(7, 63, 119, 15);

		edCrypt = new Text(this, SWT.BORDER);
		edCrypt.setBounds(132, 60, 531, 21);

		Button btCrypt = new Button(this, SWT.NONE);
		btCrypt.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				if (inputFile == null) {
					makeValidationDialog("Escolha o arquivo a ser criptografado");
					btFileChooser.setFocus();
					return;
				}
				String destFile = edDest.getText().trim();
				if (destFile.isEmpty()) {
					makeValidationDialog("Informe o caminho de destino");
					edDest.setFocus();
					return;
				}
				String key = edCrypt.getText().trim();
				if (key.isEmpty()) {
					makeValidationDialog("Informe a chave de criptografia");
					edCrypt.setFocus();
					return;
				}
				try {
					new AesCrypt().crypt(inputFile, destFile, key);
					JOptionPane.showMessageDialog(null, "Criptografado!\nVerifique o arquivo gerado", "Sucesso", JOptionPane.INFORMATION_MESSAGE);
				} catch (Exception e1) {
					e1.printStackTrace();
					JOptionPane.showMessageDialog(null, "Ocorreu um erro, verifique o log", "Erro", JOptionPane.ERROR_MESSAGE);
				}
			}
		});
		btCrypt.setBounds(131, 84, 533, 25);
		btCrypt.setText("Criptografar");
	}

	private void makeValidationDialog(String message) {
		JOptionPane.showMessageDialog(null, message, "Validação", JOptionPane.WARNING_MESSAGE);
	}

	@Override
	protected void checkSubclass() {
		// Disable the check that prevents subclassing of SWT components
	}
}
