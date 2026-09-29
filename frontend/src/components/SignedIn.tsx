// Every page but sign-in needs a session: without one, the app goes to /login and comes back
// to the page asked for afterwards.

import { useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { Navigate, Outlet, useLocation } from "react-router";
import { SIGNED_OUT } from "../api/client";
import { useMe } from "../api/hooks";
import { ErrorBox, Loading } from "./ui";

export function SignedIn() {
  const me = useMe();
  const queries = useQueryClient();
  const location = useLocation();
  useEffect(() => {
    const ended = () => queries.setQueryData(["me"], null);
    window.addEventListener(SIGNED_OUT, ended);
    return () => window.removeEventListener(SIGNED_OUT, ended);
  }, [queries]);
  if (me.isPending) {
    return (
      <div className="grid min-h-screen place-items-center">
        <Loading what="Checking your session" />
      </div>
    );
  }
  if (me.isError) {
    return (
      <div className="mx-auto max-w-xl px-4 py-16">
        <ErrorBox error={me.error} />
      </div>
    );
  }
  if (!me.data) {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  }
  return <Outlet />;
}
