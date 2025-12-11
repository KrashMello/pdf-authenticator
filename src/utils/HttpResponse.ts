import { HttpException, HttpStatus } from "@nestjs/common";

type MessageType = "warning" | "success" | "danger" | "info";

interface Opt {
  data: string | Record<string, any>;
  type?: MessageType;
  status: HttpStatus | number;
}

export const HttpResponse = (opt: Opt) => {
  const { status, data, type } = opt;
  const message = typeof data === "string" ? data.toUpperCase() : data;

  if ([200, 201].includes(status)) {
    throw new HttpException({
      status,
      type: type ?? "success",
      data: message,
    }, status);
  }

  throw new HttpException(
    {
      status,
      type: type ?? "danger",
      data: message || "Error no manejado",
    },
    status
  )
};