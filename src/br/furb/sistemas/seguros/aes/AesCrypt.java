package br.furb.sistemas.seguros.aes;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

import br.furb.sistemas.seguros.utils.CryptUtils;
import br.furb.sistemas.seguros.utils.RoundKeyUtils;

/**
 * Implementação do algoritmo de criptografia AES.
 */
public class AesCrypt {

	private static PrintWriter logWriter;
	private static PrintWriter outputWriter;

	public void crypt(File fileToCrypt, String destFile, String key) throws Exception {
		try (PrintWriter outputWriter = new PrintWriter(new FileWriter(destFile))) {
			AesCrypt.outputWriter = outputWriter;
			String logFile = new File(destFile).getParent() + File.separator + "log_criptografia.txt";
			try (PrintWriter logWriter = new PrintWriter(new FileWriter(logFile))) {
				AesCrypt.logWriter = logWriter;
	
				// pegar a matriz da chave
				String[][] keyMatrix = CryptUtils.getKeyMatrix(key);
				doLog("**** Chave ****");
				doRoundKeyLog(keyMatrix);
	
				// gerar as chaves
				KeySchedule keySchedule = new KeySchedule(keyMatrix);
				List<String[][]> roundKeys = keySchedule.getRoundKeys();
	
				// criptografar os blocos gerados do arquivo de entrada
				List<String[][]> cryptedMatrices = new ArrayList<>();
				List<String[][]> fileMatrices = CryptUtils.getMatricesFileToCrypt(fileToCrypt);
				fileMatrices.forEach(fileMatrix -> {
					doLog("**** Texto simples ****");
					doRoundKeyLog(fileMatrix);
	
					String[][] cryptedMatrix = RoundKeyUtils.doXor(fileMatrix, keyMatrix);
					doLog("**** AddRoundKey-Round 0 ****");
					doRoundKeyLog(cryptedMatrix);
	
					// 10 repetições utilizando as Round Key geradas
					for (int i = 1; i < 11; i++) {
						cryptedMatrix = RoundKeyUtils.doSubBytes(cryptedMatrix);
						doLog("**** SubBytes-Round " + i + " ****");
						doRoundKeyLog(cryptedMatrix);
	
						cryptedMatrix = RoundKeyUtils.doShiftRows(cryptedMatrix);
						doLog("**** ShiftRows-Round " + i + " ****");
						doRoundKeyLog(cryptedMatrix);
	
						// na última operação não deve ser feito a mixagem das colunas
						if (i < 10) {
							cryptedMatrix = RoundKeyUtils.doMixColumns(cryptedMatrix);
							doLog("**** MixedColumns-Round " + i + " ****");
							doRoundKeyLog(cryptedMatrix);
						}
	
						cryptedMatrix = RoundKeyUtils.doXor(cryptedMatrix, roundKeys.get(i));
						doLog("**** addRoundKey-Round " + i + " ****");
						doRoundKeyLog(cryptedMatrix);
					}
	
					doLog("**** Texto cifrado ****");
					doRoundKeyLog(cryptedMatrix);
					cryptedMatrices.add(cryptedMatrix);
				});
				doOutput(cryptedMatrices);
			}
		}
	}

	/**
	 * Realiza o log das operações no arquivo de saída.
	 * 
	 * @param log texto a ser escrito no arquivo de saída
	 */
	public static void doLog(String log) {
		try {
			AesCrypt.logWriter.write(new String(log.getBytes("UTF-8")));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Escreve no arquivo a criptografia calculada.
	 * 
	 * @param cryptedMatrices matrizes com blocos criptografados
	 */
	public static void doOutput(List<String[][]> cryptedMatrices) {
		cryptedMatrices.forEach(matrix -> {
			for (int line = 0; line < matrix.length; line++) {
				for (int column = 0; column < matrix.length; column++) {
					try {
						String output = matrix[line][column];
						AesCrypt.outputWriter.write(new String(output.getBytes("UTF-8")));
					} catch (UnsupportedEncodingException e) {
						e.printStackTrace();
					}
				}
			}
		});
	}

	/**
	 * Formata uma Round Key em uma tabela dimensional 4x4 e exibe no log.
	 * 
	 * @param roundKey Round Key (matriz) a ser escrita no log
	 */
	public static void doRoundKeyLog(String[][] roundKey) {
		StringBuilder sb = new StringBuilder("\n");
		for (int line = 0; line < roundKey.length; line++) {
			for (int column = 0; column < roundKey.length; column++) {
				sb.append(CryptUtils.formatHex(roundKey[line][column]) + " ");
			}
			sb.append("\n");
		}
		sb.append("\n");
		doLog(sb.toString());
	}

}
