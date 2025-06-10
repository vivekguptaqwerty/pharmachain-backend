export interface SignupData {
  name: string;
  phone: string;
  email: string;
  password: string;
  businessName: string;
  address: string;
  role: string;
  documents: Record<string, File>;
  id?: string;
}

export interface ErrorResponse {
  message: string;
  status?: number;
}