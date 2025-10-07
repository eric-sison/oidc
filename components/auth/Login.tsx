"use client";

import { FunctionComponent, useState } from "react";
import { Input } from "../ui/Input";
import { Button } from "../ui/Button";
import { useMutation } from "@tanstack/react-query";
import { authClient } from "@/lib/auth-client";
import { useRouter, useSearchParams } from "next/navigation";

export const LoginForm: FunctionComponent = () => {
  const [email, setEmail] = useState("ericsison.dev@gmail.com");
  const [password, setPassword] = useState("password");
  const router = useRouter();
  const searchParams = useSearchParams();

  const { mutate } = useMutation({
    mutationKey: ["register-user"],
    mutationFn: async () => {
      return await authClient.signIn.email({
        email,
        password,
        fetchOptions: {
          onSuccess: () => {
            router.push(`/api/oidc/authorize?${searchParams.toString()}`);
          },
        },
      });
    },
  });

  return (
    <div className="flex h-screen w-screen items-center justify-center">
      <div className="w-96 space-y-2">
        <Input value={email} onChange={(e) => setEmail(e.target.value)} type="email" placeholder="email" />
        <Input
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          type="password"
          placeholder="password"
        />
        <Button onClick={() => mutate()}>Login</Button>
      </div>
    </div>
  );
};
