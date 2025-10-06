import { LoginForm } from "@/components/auth/Login";
import { $oidc } from "@/server/app";
import { AuthorizationRequest } from "@/shared/types/oidc";
import { type Metadata } from "next";

export const metadata: Metadata = {
  title: "Login",
};

export default async function LoginPage(props: PageProps<"/auth/login">) {
  const searchParams = (await props.searchParams) as AuthorizationRequest;

  try {
    await $oidc.authorization.validateRequest(searchParams);
    return <LoginForm />;
  } catch (error) {
    return <>Something went wrong!</>;
  }
}
