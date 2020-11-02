package br.furb.sistemas.seguros.utils;

import java.util.List;

import br.furb.sistemas.seguros.aes.AesConstants;

/**
 * Preenchimento PKCS#5 para os blocos gerados do arquivo de cifragem.<br>
 * Defini��o:<br>
 * Preenche o �ltimo bloco com bytes cujo valor � igual � quantidade de bytes faltantes para preencher o bloco.<br>
 * Quando o �ltimo bloco n�o precisa de preenchimento, ainda assim � gerado um bloco adicional.
 */
public class Pkcs5 {

	/**
	 * Preenche as matrizes com os bytes correspondentes para os valores nulos.<br>
	 * Se a �ltima matriz estiver totalmente preenchida ser� gerada uma nova com todo o c�lculo do preenchimento.
	 * 
	 * @param matrices lista de matrizes a preencher
	 */
	public static void doPadding(List<String[][]> matrices) {
		// se a �ltima matriz n�o precisar de preenchimento vamos incluir mais uma "vazia"
		int qtyForPaddingLastMatrix = numberForPadding(matrices.get(matrices.size() - 1));
		boolean newEmptyMatrix = qtyForPaddingLastMatrix == 0;
		matrices.forEach(matrix -> {
			doPadding(matrix);
		});
		if (newEmptyMatrix) {
			int length = AesConstants.MATRIX_LENGTH;
			String[][] emptyMatrix = new String[length][length];
			doPadding(emptyMatrix);
			matrices.add(emptyMatrix);
		}
	}

	/**
	 * Preenche a matriz com os bytes correspondentes para os valores nulos (se houver).
	 * 
	 * @param matrix matriz de preenchimento
	 */
	private static void doPadding(String[][] matrix) {
		int numberForPadding = numberForPadding(matrix);
		if (numberForPadding == 0) {
			return;
		}
		for (int line = 0; line < matrix.length; line++) {
			for (int column = 0; column < matrix.length; column++) {
				String value = matrix[line][column];
				if (value == null) {
					matrix[line][column] = Integer.toHexString(numberForPadding);
				}
			}
		}
	}

	/**
	 * Percorre a matriz e descobre quantos objetos est�o nulos.<br>
	 * Esse valor define o n�mero de preenchimento desses valores nulos.
	 * 
	 * @param matrix matriz para verifica��o
	 * @return quantidade de objetos nulos na matriz
	 */
	private static int numberForPadding(String[][] matrix) {
		int counter = 0;
		for (int line = 0; line < matrix.length; line++) {
			for (int column = 0; column < matrix.length; column++) {
				String value = matrix[line][column];
				if (value == null) {
					counter++;
				}
			}
		}
		return counter;
	}

}
