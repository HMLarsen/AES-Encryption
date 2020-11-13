package br.furb.sistemas.seguros.aes;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import br.furb.sistemas.seguros.utils.CryptUtils;
import br.furb.sistemas.seguros.utils.RoundKeyUtils;

/**
 * Implementação do algoritmo de criptografia AES.
 */
public class AesCrypt {

	private static PrintWriter logWriter;

	/**
	 * Realiza a operação de criptografia AES.
	 * 
	 * @param fileToCrypt arquivo a ser cifrado
	 * @param destFile    arquivo criptografado a ser gerado
	 * @param key         chave da criptografia
	 * @throws Exception
	 */
	public void crypt(File fileToCrypt, String destFile, String key) throws Exception {
		List<String[][]> cryptedMatrices = new ArrayList<>();
		String logFile = new File(destFile).getParent() + File.separator + "log_operations.txt";

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
		}

		// geração do output
		if (cryptedMatrices.isEmpty()) {
			throw new Exception("Os blocos cifrados estão vazios.");
		}
		doOutput(destFile, cryptedMatrices);
	}

	/**
	 * Realiza o log das operações no arquivo de saída.
	 * 
	 * @param log texto a ser escrito no arquivo de saída
	 */
	public static void doLog(String log) {
		try {
			byte[] bytes = log.getBytes("UTF-8");
			logWriter.write(new String(bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
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

	/**
	 * Escreve no arquivo de saída a criptografia calculada.
	 * 
	 * @param destFile        caminho do arquivo de saída
	 * @param cryptedMatrices matrizes com blocos criptografados
	 * @throws Exception
	 */
	public static void doOutput(String destFile, List<String[][]> cryptedMatrices) throws Exception {
		try (OutputStream outputWriter = new FileOutputStream(destFile)) {
			cryptedMatrices.forEach(matrix -> {
				for (int line = 0; line < matrix.length; line++) {
					for (int column = 0; column < matrix.length; column++) {
						String hex = matrix[line][column];
						int intValue = CryptUtils.hexToInt(hex);
						try {
							outputWriter.write(intValue);
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
				}
			});
		}
	}

}
