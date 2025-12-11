export class VerifyPdfDto {
  hash: string;
  signature: string;
  pdfBase64?: string;
}
