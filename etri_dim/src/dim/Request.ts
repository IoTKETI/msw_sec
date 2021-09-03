export default interface Request {
  id: number;
  clientId: string;
  method: string;
  type: string;
  sessionId: number;
  data: string;
  metadata?: string;
}
