"use client";

import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { authClient } from "@/lib/auth-client";
import { useMutation } from "@tanstack/react-query";
import { useState } from "react";

export default function RegisterPage() {
  const [fname, setFname] = useState("");
  const [mname, setmName] = useState("");
  const [lname, setLname] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const { mutate } = useMutation({
    mutationKey: ["register-user"],
    mutationFn: async () => {
      return await authClient.signUp.email({
        email,
        password,
        name: `${fname} ${lname}`,
        familyName: lname,
        givenName: fname,
        middleName: mname,
        isActive: true,
      });
    },
  });

  return (
    <div className="flex h-screen w-screen items-center justify-center">
      <div className="w-96 space-y-4">
        <Input
          value={fname}
          onChange={(e) => setFname(e.target.value)}
          type="text"
          placeholder="first name"
        />
        <Input
          value={mname}
          onChange={(e) => setmName(e.target.value)}
          type="text"
          placeholder="middle name"
        />
        <Input value={lname} onChange={(e) => setLname(e.target.value)} type="text" placeholder="last name" />
        <Input value={email} onChange={(e) => setEmail(e.target.value)} type="email" placeholder="email" />
        <Input
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          type="password"
          placeholder="password"
        />
        <Button
          onClick={() => {
            console.log({ fname, mname, lname, email, password });
            mutate();
          }}
        >
          Register
        </Button>
      </div>
    </div>
  );
}
