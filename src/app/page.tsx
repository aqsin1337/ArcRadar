import { redirect } from "next/navigation";
import { getPageAuth } from "@/lib/auth/session";

/** No content of its own: send visitors to the app, or to sign in. */
export default async function Home() {
  const auth = await getPageAuth();
  // Disabled or unavailable states are explained by the app layout, so they go to the app too.
  redirect(auth.status === "signed_out" ? "/login" : "/dashboard");
}
