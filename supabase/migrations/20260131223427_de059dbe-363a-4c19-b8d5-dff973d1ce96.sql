-- Fix Storage Bucket Policies - Make them ownership-aware
-- First drop existing overly permissive policies
DROP POLICY IF EXISTS "Users can view documents they have access to" ON storage.objects;
DROP POLICY IF EXISTS "Users can upload documents" ON storage.objects;
DROP POLICY IF EXISTS "Users can delete own documents" ON storage.objects;

-- Create proper storage policies that verify patient ownership

-- SELECT: Doctors can view all documents, patients can only view their own
CREATE POLICY "Authorized users can view documents"
ON storage.objects FOR SELECT
USING (
  bucket_id = 'documents' AND
  auth.role() = 'authenticated' AND
  (
    -- Doctors can access all documents
    public.get_user_role(auth.uid()) = 'doctor'::public.user_role
    OR
    -- Patients can only access documents for their own patient record
    EXISTS (
      SELECT 1 FROM public.patients p
      JOIN public.documents d ON d.patient_id = p.id
      WHERE p.owner_patient_profile_id = auth.uid()
      AND storage.objects.name LIKE '%' || d.id::text || '%'
    )
    OR
    -- Alternative: Check if the storage path matches a patient they own
    EXISTS (
      SELECT 1 FROM public.patients p
      WHERE p.owner_patient_profile_id = auth.uid()
      AND storage.objects.name LIKE 'patient/' || p.id::text || '/%'
    )
  )
);

-- INSERT: Only authenticated users can upload, and they must be uploading to a patient they have access to
CREATE POLICY "Authorized users can upload documents"
ON storage.objects FOR INSERT
WITH CHECK (
  bucket_id = 'documents' AND
  auth.role() = 'authenticated' AND
  (
    -- Doctors can upload to any patient folder
    public.get_user_role(auth.uid()) = 'doctor'::public.user_role
    OR
    -- Patients can only upload to their own patient folder
    EXISTS (
      SELECT 1 FROM public.patients p
      WHERE p.owner_patient_profile_id = auth.uid()
      AND storage.objects.name LIKE 'patient/' || p.id::text || '/%'
    )
  )
);

-- DELETE: Only allow deletion by document owners or doctors
CREATE POLICY "Authorized users can delete documents"
ON storage.objects FOR DELETE
USING (
  bucket_id = 'documents' AND
  auth.role() = 'authenticated' AND
  (
    -- Doctors can delete any documents
    public.get_user_role(auth.uid()) = 'doctor'::public.user_role
    OR
    -- Patients can only delete documents in their own patient folder
    EXISTS (
      SELECT 1 FROM public.patients p
      WHERE p.owner_patient_profile_id = auth.uid()
      AND storage.objects.name LIKE 'patient/' || p.id::text || '/%'
    )
  )
);